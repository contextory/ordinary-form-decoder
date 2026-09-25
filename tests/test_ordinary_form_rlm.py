from __future__ import annotations

import json
import os
import struct
import sys
import tempfile
import unittest
from pathlib import Path
from xml.etree import ElementTree as ET

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from ordinary_form_rlm import (
	CHAIN_END,
	EventMapping,
	EventObservation,
	convert_form_bin,
	convert_tree,
	decode_event_record,
	extract_command_bar_actions,
	extract_controls,
	extract_events,
	infer_event_mappings,
	load_event_map,
	load_event_vocabulary,
	normalize_procedure_signature,
	prepare_event_mapping,
	procedure_signature,
	write_rlm_form,
)


def _document(payload: bytes) -> bytes:
	header = f"\r\n{len(payload):x} {len(payload):x} {CHAIN_END:x}\r\n".encode("ascii")
	return header + payload


def _descriptor(name: str) -> bytes:
	return bytes(20) + (name + "\0").encode("utf-16le")


def _sample_form_bin(module: bytes, form: bytes = b"{0,0,{0,0,{0}}}") -> bytes:
	streams = (("form", form), ("module", module))
	directory_size = len(streams) * 12
	offset = 16 + len(_document(bytes(directory_size)))
	directory: list[bytes] = []
	documents: list[bytes] = []
	for name, payload in streams:
		descriptor = _document(_descriptor(name))
		descriptor_at = offset
		offset += len(descriptor)
		payload_document = _document(payload)
		payload_at = offset
		offset += len(payload_document)
		directory.append(struct.pack("<3i", descriptor_at, payload_at, CHAIN_END))
		documents.extend((descriptor, payload_document))
	header = struct.pack("<4i", CHAIN_END, 512, len(streams), 0)
	return header + _document(b"".join(directory)) + b"".join(documents)


class OrdinaryFormRlmTests(unittest.TestCase):
	def test_command_bar_actions_follow_button_uuids_across_groups(self) -> None:
		first_id = "00000000-0000-0000-0000-000000000011"
		second_id = "00000000-0000-0000-0000-000000000022"
		built_in_id = "00000000-0000-0000-0000-000000000033"
		items = [
			"5", "root", "3", "1", "3",
			["6", first_id, "1", "event", ["3", "ПроизвольныйОбработчик"], "0"],
			["6", second_id, "1", "event", ["3", "МенюВложенноеНажатие"], "0"],
			["6", built_in_id, "1", "event", ["1", "00000000-0000-0000-0000-000000000044"], "0"],
			"2",
			["5", "group-a", "4", "0", "2", first_id, ["8", "Пересчитать"], built_in_id, ["8", "Закрыть"]],
			["5", "group-b", "4", "0", "1", second_id, ["8", "ВложеннаяКоманда"]],
		]
		bar = [
			"e69bf21d-97b2-4f37-86db-675aea9ec2cb", "15",
			["1", [["0"], "0", "0", "0", "0", "0", "0", items]],
			["14", "КоманднаяПанель"],
		]

		commands = extract_command_bar_actions([bar])

		self.assertEqual(
			[(item.name, item.handler, item.source_id) for item in commands],
			[
				("КоманднаяПанель.Пересчитать", "ПроизвольныйОбработчик", first_id),
				("КоманднаяПанель.ВложеннаяКоманда", "МенюВложенноеНажатие", second_id),
			],
		)
		with tempfile.TemporaryDirectory() as directory:
			summary = write_rlm_form([bar], b"", Path(directory))
			root = ET.parse(Path(directory) / "Form.xml").getroot()
			self.assertEqual(
				[(item.get("name"), item.findtext("{*}Action")) for item in root.findall("{*}Commands/{*}Command")],
				[("КоманднаяПанель.Пересчитать", "ПроизвольныйОбработчик"),
				 ("КоманднаяПанель.ВложеннаяКоманда", "МенюВложенноеНажатие")],
			)
			self.assertEqual(summary["commands"], 2)
			self.assertEqual(summary["handlers"], 2)

	def test_graphical_schema_event_uses_confirmed_platform_id(self) -> None:
		event = decode_event_record(
			["0", "e1692cc2-605b-4535-84dd-28440238746c", ["3", "КартаМаршрутаВыбор"]],
			"GraphicalSchemaField", "КартаМаршрута", {},
		)
		self.assertIsNotNone(event)
		self.assertEqual(event.name, "Выбор")
		self.assertEqual(event.resolution, "platform")

	def test_non_numeric_event_id_is_not_an_event_binding(self) -> None:
		event = decode_event_record(
			["#", "e1692cc2-605b-4535-84dd-28440238746c", ["3", "1e512aab-1b41-4ef6-9375-f0137be9dd91"]],
			"InputField", "Вид", {},
		)
		self.assertIsNone(event)

	def test_table_collision_prefers_known_handler_suffix(self) -> None:
		event = decode_event_record(
			["44", "e1692cc2-605b-4535-84dd-28440238746c", ["3", "ПараметрыПриОкончанииРедактирования"]],
			"Table", "Параметры", {("Table", "44"): EventMapping("ПередОкончаниемРедактирования", "statistics")},
		)
		self.assertIsNotNone(event)
		self.assertEqual(event.name, "ПриОкончанииРедактирования")
		self.assertEqual(event.resolution, "statistics+lexical-conflict")

	def test_form_event_without_local_procedure_keeps_platform_name(self) -> None:
		event = decode_event_record(
			["70012", "e1692cc2-605b-4535-84dd-28440238746c", ["3", "ОбработкаПроверкиЗаполнения"]],
			"Form", "", {},
		)
		self.assertIsNotNone(event)
		self.assertEqual(event.name, "ОбработкаПроверкиЗаполнения")
		self.assertEqual(event.resolution, "platform")

	@staticmethod
	def observation(
		control_type: str,
		control_name: str,
		source_id: str,
		handler: str,
		form: str,
	) -> EventObservation:
		return EventObservation(
			control_type, control_name, source_id, handler, form, form, form,
			f"Процедура {handler}(Элемент)",
		)

	def test_unanimous_form_mapping_is_accepted_with_one_observation(self) -> None:
		observations = [
			self.observation("Form", "", "70002", "ПередЗакрытием", f"Документ.{name}.Форма.ФормаДокумента")
			for name in "АБВГД"
		]
		observations.append(
			self.observation("Form", "", "70012", "ОбработкаПроверкиЗаполнения", "Документ.Е.Форма.ФормаДокумента")
		)

		event_map, details, unresolved, outliers, ignored = infer_event_mappings(observations, {})

		self.assertEqual(event_map[("Form", "70002")].event_name, "ПередЗакрытием")
		self.assertEqual(event_map[("Form", "70012")].event_name, "ОбработкаПроверкиЗаполнения")
		self.assertEqual(details["Form"]["70012"]["evidence"]["decision"], "unanimous")
		self.assertEqual(unresolved, [])
		self.assertEqual(outliers, [])
		self.assertEqual(ignored, [])

	def test_handler_without_control_name_is_excluded_from_voting(self) -> None:
		observations = [
			self.observation(
				"InputField",
				f"Поле{index}",
				"10",
				f"{'пОЛЕ' if index == 0 else 'Поле'}{index}ПриИзменении",
				f"Форма{index % 3}",
			)
			for index in range(5)
		]
		observations.extend(
			self.observation("InputField", f"Реквизит{index}", "10", f"Обработать{index}", f"Форма{index % 3}")
			for index in range(20)
		)

		event_map, details, unresolved, outliers, _ = infer_event_mappings(observations, {})

		self.assertEqual(event_map[("InputField", "10")].event_name, "ПриИзменении")
		self.assertEqual(unresolved, [])
		self.assertEqual(outliers, [])
		self.assertEqual(details["InputField"]["10"]["evidence"]["eligible_votes"], 5)
		self.assertEqual(details["InputField"]["10"]["evidence"]["excluded_observations"], 20)

	def test_statistical_majority_accepts_outliers_above_threshold(self) -> None:
		observations = [
			self.observation("InputField", f"Поле{index}", "10", f"Поле{index}ПриИзменении", f"Форма{index % 4}")
			for index in range(8)
		]
		observations.extend(
			self.observation("InputField", f"Ошибка{index}", "10", f"Ошибка{index}Открытие", f"Форма{index}")
			for index in range(2)
		)

		event_map, _, unresolved, outliers, _ = infer_event_mappings(observations, {})

		self.assertEqual(event_map[("InputField", "10")].event_name, "ПриИзменении")
		self.assertEqual(unresolved, [])
		self.assertEqual(outliers[0]["candidate_names"], {"Открытие": 2, "ПриИзменении": 8})
		self.assertEqual(len(outliers[0]["minority_occurrences"]), 2)

	def test_statistical_majority_rejects_result_below_ratio(self) -> None:
		observations = [
			self.observation("InputField", f"Поле{index}", "10", f"Поле{index}ПриИзменении", f"Форма{index % 4}")
			for index in range(7)
		]
		observations.extend(
			self.observation("InputField", f"Ошибка{index}", "10", f"Ошибка{index}Открытие", f"Форма{index}")
			for index in range(3)
		)

		event_map, _, unresolved, _, _ = infer_event_mappings(observations, {})

		self.assertNotIn(("InputField", "10"), event_map)
		self.assertEqual(unresolved[0]["confidence"], 0.7)

	def test_multiline_procedure_signature_is_found_and_normalized(self) -> None:
		module = """Процедура Обработка(
		Знач Элемент,
		Область,
		СтандартнаяОбработка = Истина)
	КонецПроцедуры
	""".encode("utf-8")

		signature = procedure_signature(module, "Обработка")

		self.assertIn("СтандартнаяОбработка = Истина", signature)
		self.assertEqual(normalize_procedure_signature(signature), "(элемент,область,стандартнаяобработка)")

	def test_observation_without_procedure_is_ignored(self) -> None:
		observation = EventObservation(
			"InputField", "Поле", "10", "ПолеПриИзменении", "Форма", "Форма", "Модуль", "",
		)

		event_map, _, unresolved, _, ignored = infer_event_mappings([observation], {})

		self.assertEqual(event_map, {})
		self.assertEqual(unresolved, [])
		self.assertEqual(ignored[0]["ignored_no_procedure"], 1)

	def test_missing_procedure_does_not_affect_existing_candidate(self) -> None:
		valid = self.observation("InputField", "Поле", "10", "ПолеПриИзменении", "Форма1")
		missing = EventObservation(
			"InputField", "Ошибка", "10", "ОшибкаПриАктивации", "Форма2", "Форма2", "Модуль", "",
		)

		event_map, details, unresolved, _, _ = infer_event_mappings([valid, missing], {})

		self.assertEqual(event_map[("InputField", "10")].event_name, "ПриИзменении")
		evidence = details["InputField"]["10"]["evidence"]
		self.assertEqual(evidence["usable_observations"], 1)
		self.assertEqual(evidence["ignored_no_procedure"], 1)
		self.assertEqual(evidence["eligible_votes"], 1)
		self.assertEqual(unresolved, [])

	def test_known_suffix_from_different_handlers_resolves_table_event(self) -> None:
		observations = [
			self.observation("Table", str(index), "36", handler, f"Форма{index}")
			for index, handler in enumerate(
				(
					"ФильтрыПисемПриАктивизацииКолонки",
					"ТаблицаПравДоступаПриАктивизацииКолонки",
					"ТоварыИУслугиПриАктивизацииКолонки",
				)
			)
		]

		event_map, details, unresolved, _, _ = infer_event_mappings(observations, {})

		self.assertEqual(event_map[("Table", "36")].event_name, "ПриАктивизацииКолонки")
		self.assertEqual(
			details["Table"]["36"]["evidence"]["known_suffix_candidates"],
			{"ПриАктивизацииКолонки": 3},
		)
		self.assertEqual(unresolved, [])

	def test_known_suffix_uses_longest_event_name(self) -> None:
		observation = self.observation("InputField", "ДругоеПоле", "15", "ПолеНачалоПеретаскивания", "Форма")

		event_map, details, _, _, _ = infer_event_mappings(
			[observation], {}, {"Перетаскивания", "НачалоПеретаскивания"},
		)

		self.assertEqual(event_map[("InputField", "15")].event_name, "НачалоПеретаскивания")
		self.assertEqual(
			details["InputField"]["15"]["evidence"]["known_suffix_candidates"],
			{"НачалоПеретаскивания": 1},
		)

	def test_event_vocabulary_contains_control_and_extension_events(self) -> None:
		dictionary = load_event_vocabulary()
		vocabulary_path = Path(__file__).resolve().parents[1] / "ordinary-form-events.json"
		document = json.loads(vocabulary_path.read_text(encoding="utf-8"))
		self.assertEqual(set(document), {"schema_version", "events_by_control"})

		self.assertIn("ОбработкаПроверкиЗаполнения", dictionary["Form"])
		self.assertIn("ПередРазворачиванием", dictionary["Table"])
		self.assertIn("Создание", dictionary["InputField"])
		self.assertIn("ОкончаниеВводаТекста", dictionary["ChoiceField"])
		self.assertIn("onclick", dictionary["HTMLDocumentField"])

	def test_direct_candidate_is_normalized_to_known_event_suffix(self) -> None:
		observation = self.observation(
			"InputField", "Поле", "2147483647", "ПолеаПриИзменении", "Форма",
		)

		event_map, details, unresolved, _, _ = infer_event_mappings([observation], {})

		self.assertEqual(event_map[("InputField", "2147483647")].event_name, "ПриИзменении")
		self.assertEqual(details["InputField"]["2147483647"]["evidence"]["raw_direct_candidates"], {"аПриИзменении": 1})
		self.assertEqual(unresolved, [])

	def test_known_events_are_scoped_by_control_type(self) -> None:
		observation = self.observation("Panel", "Панель", "0", "ПанельВыбор", "Форма")

		event_map, _, unresolved, _, _ = infer_event_mappings([observation], {})

		self.assertNotIn(("Panel", "0"), event_map)
		self.assertEqual(unresolved[0]["eligible_votes"], 0)

	def test_inferred_suffix_must_be_a_known_event_for_control_type(self) -> None:
		observations = [
			self.observation("Panel", "ПанельА", "0", "ПанельАВыбор", "ФормаА"),
			self.observation("Panel", "ПанельБ", "0", "ПанельБВыбор", "ФормаБ"),
		]

		event_map, _, unresolved, _, _ = infer_event_mappings(observations, {})

		self.assertNotIn(("Panel", "0"), event_map)
		self.assertEqual(unresolved[0]["eligible_votes"], 0)

	def test_repeated_identical_arbitrary_handler_does_not_create_suffix(self) -> None:
		observations = [
			self.observation("Panel", f"Панель{index}", "2", "ОбработатьЧтоТо", f"Форма{index}")
			for index in range(10)
		]

		event_map, _, unresolved, _, _ = infer_event_mappings(observations, {})

		self.assertNotIn(("Panel", "2"), event_map)
		self.assertEqual(unresolved[0]["eligible_votes"], 0)

	def test_mixed_semantics_blocks_manual_mapping(self) -> None:
		handlers = (
			("ДеревоПередИзменениемРодителя", "Процедура ДеревоПередИзменениемРодителя(Элемент, Отказ)"),
			("СписокПередРазворачиванием", "Процедура СписокПередРазворачиванием(Элемент, Строка, Отказ)"),
			("ТаблицаПередУстановкойПометкиУдаления", "Процедура ТаблицаПередУстановкойПометкиУдаления(Элемент, Отказ)"),
		)
		observations = [
			EventObservation("Table", handler.removesuffix(event), "10000", handler, f"Форма{index}", f"Форма{index}", "Модуль", signature)
			for index, (handler, signature) in enumerate(handlers)
			for event in (handler[handler.find("Перед"):],)
		]
		manual = {("Table", "10000"): EventMapping("ПередРазворачиванием", "manual")}

		event_map, _, unresolved, _, _ = infer_event_mappings(observations, manual)

		self.assertNotIn(("Table", "10000"), event_map)
		self.assertTrue(unresolved[0]["mixed_semantics"])
		self.assertEqual(unresolved[0]["status"], "manual_with_mixed_semantics")
		self.assertEqual(unresolved[0]["event_name"], "ПередРазворачиванием")

	def test_manual_mapping_wins_and_conflict_is_reported(self) -> None:
		observations = [
			self.observation("InputField", "Поле", "10", "ПолеПриИзменении", "Документ.А.Форма.Форма"),
			self.observation("InputField", "Поле2", "10", "Поле2ПриИзменении", "Документ.Б.Форма.Форма"),
		]
		manual = {("InputField", "10"): EventMapping("Открытие", "manual")}

		event_map, _, unresolved, _, _ = infer_event_mappings(observations, manual)

		self.assertEqual(event_map[("InputField", "10")].event_name, "Открытие")
		self.assertEqual(unresolved[0]["conflict_with_mapping"], "Открытие")

	def test_parent_control_does_not_capture_nested_control_events(self) -> None:
		event_uuid = "00000000-0000-0000-0000-000000000001"
		parent_event = ["1", event_uuid, ["3", "ПанельСобытие"]]
		child_event = ["2", event_uuid, ["3", "ПолеСобытие"]]
		child = ["381ed624-9217-4e63-85db-c4c3cb87daae", "child", child_event]
		parent = ["09ccdc77-ea1a-4a6d-ab1c-3435eada2433", "parent", parent_event, child]

		events = extract_events(parent, "Panel", "Панель", {})

		self.assertEqual([(event.source_id, event.handler) for event in events], [("1", "ПанельСобытие")])

	def test_recognized_spreadsheet_field_owns_its_events(self) -> None:
		event_uuid = "00000000-0000-0000-0000-000000000001"
		child = [
			"236a17b3-7f44-46d9-a907-75f9cdc61ab5",
			"child",
			["14", "ТабличныйДокумент"],
			["7", event_uuid, ["3", "ТабличныйДокументПриИзмененииСодержимогоОбласти"]],
		]
		parent = [
			"09ccdc77-ea1a-4a6d-ab1c-3435eada2433", "parent", ["14", "Панель"], child,
		]

		controls = extract_controls([parent])

		self.assertEqual(controls[0].type, "Panel")
		self.assertEqual(controls[0].events, ())
		self.assertEqual(controls[0].children[0].type, "SpreadsheetDocumentField")
		self.assertEqual(controls[0].children[0].events[0].control_type, "SpreadsheetDocumentField")

	def test_picture_decoration_owns_its_event_instead_of_parent_panel(self) -> None:
		event_uuid = "00000000-0000-0000-0000-000000000001"
		picture = [
			"151ef23e-6bb2-4681-83d0-35bc2217230c",
			"picture",
			["14", "Картинка"],
			["0", event_uuid, ["3", "КартинкаНажатие"]],
		]
		panel = [
			"09ccdc77-ea1a-4a6d-ab1c-3435eada2433", "panel", ["14", "Панель"], picture,
		]

		controls = extract_controls([panel])

		self.assertEqual(controls[0].type, "Panel")
		self.assertEqual(controls[0].events, ())
		self.assertEqual(controls[0].children[0].type, "PictureDecoration")
		self.assertEqual(controls[0].children[0].events[0].control_type, "PictureDecoration")

	def test_panel_pages_use_binary_page_index_and_keep_direct_children(self) -> None:
		def layout(page_index: object) -> list[object]:
			value: list[object] = ["0"] * 19
			value[18] = page_index
			return value

		def label(source_id: str, name: str, page_index: object) -> list[object]:
			return ["0fc7e20d-f241-460c-bdf4-5ad88e5474a5", source_id, ["14", name], layout(page_index)]

		def page(name: str) -> list[object]:
			return ["3", ["1", "0"], ["3", "0"], "-1", "1", "1", name, "1"]

		first = label("1", "НаПервой", "0")
		second = label("2", "НаВторой", "1")
		direct = label("3", "ВнеСтраниц", ["0", "3", "3"])
		panel = [
			"09ccdc77-ea1a-4a6d-ab1c-3435eada2433",
			"10",
			["1", ["profile", ["1", "2", page("Первая"), page("Вторая")]]],
			layout("0"),
			["14", "Панель"],
			["3", first, second, direct],
		]

		control = extract_controls([panel])[0]

		self.assertEqual([item.name for item in control.pages], ["Первая", "Вторая"])
		self.assertEqual([[item.name for item in page_info.children] for page_info in control.pages], [["НаПервой"], ["НаВторой"]])
		self.assertEqual([item.name for item in control.children], ["ВнеСтраниц"])
		with tempfile.TemporaryDirectory() as directory:
			write_rlm_form([panel], b"", Path(directory))
			xml = ET.parse(Path(directory) / "Form.xml").getroot()
			pages = xml.findall(".//{*}Panel/{*}Pages/{*}Page")
			self.assertEqual([item.get("name") for item in pages], ["Первая", "Вторая"])
			self.assertEqual([item.get("name") for item in xml.findall(".//{*}Panel/{*}ChildItems/{*}Label")], ["ВнеСтраниц"])

	def test_event_vocabulary_contains_picture_decoration_events(self) -> None:
		dictionary = load_event_vocabulary()

		self.assertIn("Нажатие", dictionary["PictureDecoration"])

	def test_table_events_are_scoped_by_extension_guid(self) -> None:
		event_uuid = "00000000-0000-0000-0000-000000000001"
		extension_guid = "9ab3fa70-d2e0-4e44-baac-730682272ed2"
		table = [
			"ea83fe3a-ac3c-4cce-8045-3dddf35b28b1",
			"table",
			["14", "Дерево"],
			[extension_guid, ["10000", event_uuid, ["3", "ДеревоПередРазворачиванием"]]],
		]

		control = extract_controls([table])[0]
		event = control.events[0]
		observation = self.observation(
			event.control_type, control.lexical_name, event.source_id, event.handler, "Форма",
		)
		event_map, _, unresolved, _, _ = infer_event_mappings([observation], {})

		self.assertEqual(event.control_type, f"Table@{extension_guid}")
		self.assertEqual(event_map[(f"Table@{extension_guid}", "10000")].event_name, "ПередРазворачиванием")
		self.assertEqual(unresolved, [])

	def test_statistical_mapping_does_not_conflict_with_manual_id(self) -> None:
		observations = [
			self.observation("InputField", f"Поле{index}", "10", f"Поле{index}ПриИзменении", f"Форма{index % 3}")
			for index in range(5)
		]
		manual = {("InputField", "99"): EventMapping("ПриИзменении", "manual")}

		event_map, _, unresolved, _, _ = infer_event_mappings(observations, manual)

		self.assertNotIn(("InputField", "10"), event_map)
		self.assertEqual(unresolved[0]["source_id"], "10")

	def test_stronger_statistical_id_wins_event_name_conflict(self) -> None:
		observations = [
			self.observation("Table", f"Таблица{index}", "35", f"Таблица{index}ПриАктивизацииСтроки", f"Форма{index}")
			for index in range(5)
		]
		observations.append(
			self.observation("Table", "ОшибочнаяТаблица", "36", "ОшибочнаяТаблицаПриАктивизацииСтроки", "ФормаОшибка")
		)

		event_map, _, unresolved, _, _ = infer_event_mappings(observations, {})

		self.assertEqual(event_map[("Table", "35")].event_name, "ПриАктивизацииСтроки")
		self.assertNotIn(("Table", "36"), event_map)
		self.assertEqual(unresolved[0]["source_id"], "36")

	def test_embedded_parser_writes_expected_package(self) -> None:
		with tempfile.TemporaryDirectory() as directory:
			root = Path(directory)
			form_bin = root / "Form.bin"
			output = root / "output"
			module = "Процедура Тест()\nКонецПроцедуры\n".encode("utf-8")
			form_bin.write_bytes(_sample_form_bin(module))

			summary = convert_form_bin(form_bin, output)

			ET.parse(output / "Form.xml")
			self.assertEqual((output / "Form" / "Module.bsl").read_bytes(), module)
			self.assertEqual(summary["controls"], 0)

	def test_project_event_state_is_bootstrapped_and_manual_answer_is_promoted(self) -> None:
		with tempfile.TemporaryDirectory() as directory:
			project = Path(directory)
			configuration = project / "src" / "cf"
			module = """Процедура ПередЗакрытием()
	КонецПроцедуры
	Процедура ОбработкаПроверкиЗаполнения()
	КонецПроцедуры
	Процедура ОбработкаОповещения()
	КонецПроцедуры
	""".encode("utf-8")
			known = '{0,0,{0,0,{0}},0,{{70002,00000000-0000-0000-0000-000000000001,{3,ПередЗакрытием}}}}'.encode("utf-8")
			rare = '{0,0,{0,0,{0}},0,{{70012,00000000-0000-0000-0000-000000000002,{3,ОбработкаПроверкиЗаполнения}}}}'.encode("utf-8")
			conflicting = '{0,0,{0,0,{0}},0,{{70012,00000000-0000-0000-0000-000000000003,{3,ОбработкаОповещения}}}}'.encode("utf-8")
			forms = (("A", known), ("B", known), ("C", known), ("D", known), ("E", known), ("F", rare), ("G", conflicting))
			for object_name, payload in forms:
				form = configuration / "Documents" / object_name / "Forms" / "Form" / "Ext"
				form.mkdir(parents=True)
				(form / "Form.bin").write_bytes(_sample_form_bin(module, payload))

			analysis = prepare_event_mapping(project, configuration)

			self.assertTrue(analysis.rebuilt)
			self.assertEqual(analysis.event_map[("Form", "70002")].event_name, "ПередЗакрытием")
			unresolved_path = project / "ordinary-forms" / "unresolved-events.json"
			unresolved = json.loads(unresolved_path.read_text(encoding="utf-8"))
			self.assertEqual(unresolved["events"][0]["source_id"], "70012")
			self.assertEqual(
				unresolved["events"][0]["occurrences"][0]["metadata_path"],
				"Документ.F.Форма.Form",
			)
			unresolved["events"][0]["event_name"] = "ОбработкаПроверкиЗаполнения"
			unresolved_path.write_text(json.dumps(unresolved, ensure_ascii=False), encoding="utf-8")

			promoted = prepare_event_mapping(project, configuration)

			self.assertEqual(
				promoted.event_map[("Form", "70012")],
				EventMapping("ОбработкаПроверкиЗаполнения", "manual"),
			)
			self.assertEqual(load_event_map(project)[("Form", "70012")].source, "manual")

	def test_analyzer_upgrade_rebuilds_current_form_outputs(self) -> None:
		with tempfile.TemporaryDirectory() as directory:
			project = Path(directory)
			configuration = project / "src" / "cf"
			form = configuration / "Documents" / "D" / "Forms" / "F" / "Ext"
			form.mkdir(parents=True)
			form_bin = form / "Form.bin"
			form_bin.write_bytes(_sample_form_bin(b""))

			first = convert_tree(configuration, configuration, False, False, project)
			form_xml = form / "Form.xml"
			module = form / "Form" / "Module.bsl"
			future = form_xml.stat().st_mtime + 3600
			os.utime(form_xml, (future, future))
			os.utime(module, (future, future))
			map_path = project / "ordinary-forms" / "event-map.json"
			payload = json.loads(map_path.read_text(encoding="utf-8"))
			payload["analyzer_version"] -= 1
			map_path.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")

			second = convert_tree(configuration, configuration, False, False, project)

			self.assertEqual(first["forms_processed"], 1)
			self.assertEqual(second["forms_processed"], 1)
			self.assertEqual(second["forms_skipped"], 0)

	def test_external_tree_uses_its_own_event_state(self) -> None:
		with tempfile.TemporaryDirectory() as directory:
			project = Path(directory) / "UPP"
			project.mkdir()
			(project / "project.toml").write_text("", encoding="utf-8")
			configuration = project / "src" / "cf"
			configuration_form = configuration / "Documents" / "D" / "Forms" / "F" / "Ext"
			configuration_form.mkdir(parents=True)
			(configuration_form / "Form.bin").write_bytes(_sample_form_bin(b""))
			prepare_event_mapping(project, configuration)
			project_map = project / "ordinary-forms" / "event-map.json"
			before = project_map.read_bytes()

			external = project / "src" / "epf" / "Sample"
			form = external / "Export" / "Forms" / "Main" / "Ext"
			form.mkdir(parents=True)
			module = "Процедура Тест()\nКонецПроцедуры\n".encode("utf-8")
			(form / "Form.bin").write_bytes(_sample_form_bin(module))
			result = convert_tree(external, external, False, True)

			self.assertEqual(result["forms_processed"], 1)
			self.assertEqual(result["forms_failed"], 0)
			ET.parse(form / "Form.xml")
			self.assertEqual((form / "Form" / "Module.bsl").read_bytes(), module)
			self.assertTrue((external / "ordinary-forms" / "event-map.json").is_file())
			self.assertEqual(project_map.read_bytes(), before)

	def test_recursive_tree_without_project_or_cf(self) -> None:
		with tempfile.TemporaryDirectory() as directory:
			root = Path(directory) / "erf" / "Sample"
			form = root / "Nested" / "Forms" / "Main" / "Ext"
			form.mkdir(parents=True)
			(form / "Form.bin").write_bytes(_sample_form_bin(b""))

			result = convert_tree(root, root, False, True)

			self.assertEqual(result["forms_processed"], 1)
			self.assertEqual(result["forms_failed"], 0)
			self.assertTrue((form / "Form.xml").is_file())


if __name__ == "__main__":
	unittest.main()
