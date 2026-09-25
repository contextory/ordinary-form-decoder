"""Read-only parser for the streams stored in an ordinary 1C Form.bin.

This program intentionally implements only the binary facts required for the
RLM conversion pipeline. It never writes Form.bin and has no dependency on
onec-ordinary-forms.
"""

from __future__ import annotations

import argparse
import functools
import json
import re
import struct
import subprocess
from collections import Counter, defaultdict
from dataclasses import dataclass
from importlib import resources
from pathlib import Path
from xml.etree import ElementTree as ET


CHAIN_END = 0x7FFFFFFF
HEADER_BYTES = 16
RLM_NAMESPACE = "http://v8.1c.ru/8.3/xcf/logform"
SCRIPT_VERSION = "0.6.3"
EVENT_SCHEMA_VERSION = 1
EVENT_ANALYZER_VERSION = 8
EVENT_DIRECTORY = "ordinary-forms"
EVENT_MAP_FILE = "event-map.json"
UNRESOLVED_EVENTS_FILE = "unresolved-events.json"
EVENT_VOCABULARY_FILE = "ordinary-form-events.json"
STATISTICAL_MIN_VOTES = 5
STATISTICAL_MIN_RATIO = 0.8
STATISTICAL_MIN_FORMS = 3

CONTROL_TYPE_BY_GUID = {
    "09ccdc77-ea1a-4a6d-ab1c-3435eada2433": "Panel",
    "0fc7e20d-f241-460c-bdf4-5ad88e5474a5": "Label",
    "151ef23e-6bb2-4681-83d0-35bc2217230c": "PictureDecoration",
    "6ff79819-710e-4145-97cd-1618da79e3e2": "Button",
    "381ed624-9217-4e63-85db-c4c3cb87daae": "InputField",
    "e69bf21d-97b2-4f37-86db-675aea9ec2cb": "CommandBar",
    "35af3d93-d7c7-4a2e-a8eb-bac87a1a3f26": "CheckBox",
    "ea83fe3a-ac3c-4cce-8045-3dddf35b28b1": "Table",
    "64483e7f-3833-48e2-8c75-2c31aac49f6e": "ChoiceField",
    "90db814a-c75f-4b54-bc96-df62e554d67d": "GroupBox",
    "782e569a-79a7-4a4f-a936-b48d013936ec": "RadioButton",
    "36e52348-5d60-4770-8e89-a16ed50a2006": "Splitter",
    "19f8b798-314e-4b4e-8121-905b2a7a03f5": "ListBox",
    "236a17b3-7f44-46d9-a907-75f9cdc61ab5": "SpreadsheetDocumentField",
    "d92a805c-98ae-4750-9158-d9ce7cec2f20": "HTMLDocumentField",
    "6c06cd5d-8481-4b6f-a90a-7a97a8bb8bef": "TrackBar",
    "e3c063d8-ef92-41be-9c89-b70290b5368b": "CalendarField",
    "e5fdc112-5c84-4a16-9728-72b85692b6e2": "GanttChart",
    "a8b97779-1a4b-4059-b09c-807f86d2a461": "Chart",
    "42248403-7748-49da-b782-e4438fd7bff3": "GraphicalSchemaField",
}

# Platform IDs confirmed from actual ordinary forms.  These mappings do not
# depend on a handler existing in the local form module.
PLATFORM_EVENT_NAMES = {
    ("Form", "70012"): "ОбработкаПроверкиЗаполнения",
    ("GraphicalSchemaField", "0"): "Выбор",
}

TABLE_EVENT_SCOPE_GUIDS = {
    "9ab3fa70-d2e0-4e44-baac-730682272ed2",
    "99f52caa-7b96-4bd4-a649-aedbd230a555",
    "8d9c2111-ed81-11d5-b9b6-0050bae0a95d",
    "6438f3ff-436d-4690-a134-d62bf247035b",
}

@dataclass(frozen=True)
class Stream:
    name: str
    payload: bytes


@dataclass(frozen=True)
class AttributeInfo:
    name: str
    types: tuple[str, ...]


@dataclass(frozen=True)
class EventInfo:
    source_id: str
    control_type: str
    name: str
    handler: str
    resolution: str


@dataclass(frozen=True)
class CommandInfo:
    name: str
    handler: str
    source_id: str


@dataclass(frozen=True)
class PageInfo:
    name: str
    children: tuple["ControlInfo", ...]


@dataclass(frozen=True)
class ControlInfo:
    source_id: str
    name: str
    type: str
    data_path: str
    events: tuple[EventInfo, ...]
    lexical_name: str
    children: tuple["ControlInfo", ...] = ()
    pages: tuple[PageInfo, ...] = ()
    is_column: bool = False


@dataclass(frozen=True)
class EventMapping:
    event_name: str
    source: str


@dataclass(frozen=True)
class EventObservation:
    control_type: str
    control_name: str
    source_id: str
    handler: str
    metadata_path: str
    source_path: str
    module_path: str
    procedure_signature: str


@dataclass(frozen=True)
class EventAnalysisResult:
    event_map: dict[tuple[str, str], EventMapping]
    rebuilt: bool
    accepted: int
    unresolved: int


class BracketSyntaxError(ValueError):
    """The textual form stream is not a complete 1C bracket value."""


class BracketReader:
    """Small parser for the list notation used by the `form` stream."""

    def __init__(self, text: str) -> None:
        self.text = text
        self.cursor = 0

    def parse(self) -> object:
        self.skip_space()
        value = self.value()
        self.skip_space()
        if self.cursor != len(self.text):
            raise BracketSyntaxError(f"Unexpected text at offset {self.cursor}")
        return value

    def value(self) -> object:
        self.skip_space()
        if self.cursor >= len(self.text):
            raise BracketSyntaxError("Unexpected end of form stream")
        if self.text[self.cursor] == "{":
            return self.list_value()
        if self.text[self.cursor] == '"':
            return self.quoted_atom()
        if self.text.startswith("#base64:", self.cursor):
            return self.base64_atom()
        return self.plain_atom()

    def list_value(self) -> list[object]:
        self.cursor += 1
        values: list[object] = []
        self.skip_space()
        if self.cursor < len(self.text) and self.text[self.cursor] == "}":
            self.cursor += 1
            return values
        while True:
            values.append(self.value())
            self.skip_space()
            if self.cursor >= len(self.text):
                raise BracketSyntaxError("Unclosed list")
            separator = self.text[self.cursor]
            self.cursor += 1
            if separator == "}":
                return values
            if separator != ",":
                raise BracketSyntaxError(f"Expected ',' or '}}' at offset {self.cursor - 1}")

    def quoted_atom(self) -> str:
        self.cursor += 1
        pieces: list[str] = []
        while self.cursor < len(self.text):
            char = self.text[self.cursor]
            self.cursor += 1
            if char != '"':
                pieces.append(char)
                continue
            if self.cursor < len(self.text) and self.text[self.cursor] == '"':
                pieces.append('"')
                self.cursor += 1
                continue
            return "".join(pieces)
        raise BracketSyntaxError("Unclosed quoted atom")

    def plain_atom(self) -> str:
        start = self.cursor
        while self.cursor < len(self.text) and self.text[self.cursor] not in ",{}\r\n\t ":
            self.cursor += 1
        if start == self.cursor:
            raise BracketSyntaxError(f"Expected value at offset {self.cursor}")
        return self.text[start:self.cursor]

    def base64_atom(self) -> str:
        """Consume a multiline unquoted base64 atom without parsing its bytes."""
        start = self.cursor
        closing_brace = self.text.find("}", start)
        if closing_brace < 0:
            raise BracketSyntaxError("Unclosed base64 atom")
        self.cursor = closing_brace
        return self.text[start:closing_brace].strip()

    def skip_space(self) -> None:
        while self.cursor < len(self.text) and self.text[self.cursor].isspace():
            self.cursor += 1


def parse_bracket_stream(payload: bytes) -> object:
    """Decode a UTF-8 form stream into nested lists and string atoms."""
    return BracketReader(payload.decode("utf-8-sig")).parse()


def extract_attributes(form_root: object) -> list[AttributeInfo]:
    """Read only the form-attribute records required by the RLM projection."""
    if not isinstance(form_root, list) or len(form_root) < 3:
        return []
    attribute_section = form_root[2]
    if not isinstance(attribute_section, list) or len(attribute_section) < 3:
        return []
    records = attribute_section[2]
    if not isinstance(records, list):
        return []

    attributes: list[AttributeInfo] = []
    for record in records[1:]:
        attribute = decode_attribute_record(record)
        if attribute is not None:
            attributes.append(attribute)
    return attributes


def decode_attribute_record(record: object) -> AttributeInfo | None:
    if not isinstance(record, list) or len(record) < 5 or not isinstance(record[4], str):
        return None
    if not record[4]:
        return None
    pattern = record[-1] if isinstance(record[-1], list) else []
    return AttributeInfo(name=record[4], types=decode_attribute_types(pattern))


def decode_attribute_types(pattern: object) -> tuple[str, ...]:
    if not isinstance(pattern, list) or len(pattern) < 2 or pattern[0] != "Pattern":
        return ()
    pattern_items = pattern[1]
    if not isinstance(pattern_items, list):
        return ()
    types: list[str] = []
    for item in pattern_items:
        if not isinstance(item, str) or not item or item == "#":
            continue
        types.append(f"cfg:uuid.{item.lower()}" if is_uuid(item) else item)
    return tuple(types)


def is_uuid(value: str) -> bool:
    pieces = value.split("-")
    return [len(piece) for piece in pieces] == [8, 4, 4, 4, 12] and all(
        character in "0123456789abcdefABCDEF" for piece in pieces for character in piece
    )


def walk_lists(value: object):
    if not isinstance(value, list):
        return
    yield value
    for child in value:
        yield from walk_lists(child)


def is_control_record(value: object) -> bool:
    return (
        isinstance(value, list)
        and len(value) >= 3
        and isinstance(value[0], str)
        and value[0].lower() in CONTROL_TYPE_BY_GUID
        and isinstance(value[1], str)
    )


def walk_owned_lists(value: object, *, root: bool = True):
    """Walk one control's records without entering nested controls."""
    if not isinstance(value, list):
        return
    yield value
    for child in value:
        if not isinstance(child, list) or (not root and is_control_record(child)):
            continue
        if root and is_control_record(child):
            continue
        yield from walk_owned_lists(child, root=False)


def walk_owned_lists_with_ancestors(
    value: object,
    ancestors: tuple[list[object], ...] = (),
    *,
    root: bool = True,
):
    """Walk owned records and retain their path for extension-sensitive events."""
    if not isinstance(value, list):
        return
    yield value, ancestors
    for child in value:
        if not isinstance(child, list) or (not root and is_control_record(child)):
            continue
        if root and is_control_record(child):
            continue
        yield from walk_owned_lists_with_ancestors(child, ancestors + (value,), root=False)


def extract_controls(form_root: object, event_map: dict[tuple[str, str], EventMapping] | None = None) -> list[ControlInfo]:
    """Find control records by their class GUID, independently of list order."""
    seen: set[tuple[str, str]] = set()
    return discover_controls(form_root, seen, event_map or {})


def discover_controls(
    value: object,
    seen: set[tuple[str, str]],
    event_map: dict[tuple[str, str], EventMapping],
) -> list[ControlInfo]:
    if not isinstance(value, list):
        return []
    control_type = CONTROL_TYPE_BY_GUID.get(value[0].lower()) if len(value) >= 3 and isinstance(value[0], str) else None
    if control_type is not None and isinstance(value[1], str):
        key = (value[0].lower(), value[1])
        if key in seen:
            return []
        seen.add(key)
        return [decode_control(value, control_type, discover_controls(value[2:], seen, event_map), event_map)]
    controls: list[ControlInfo] = []
    for child in value:
        controls.extend(discover_controls(child, seen, event_map))
    return controls


def decode_control(
    candidate: list[object],
    control_type: str,
    nested_children: list[ControlInfo],
    event_map: dict[tuple[str, str], EventMapping],
) -> ControlInfo:
    """Project one identified control record into the small RLM model."""
    lexical_name = control_metadata_name(candidate)
    name = lexical_name or f"{control_type}_{candidate[1]}"
    data_path = name if control_type in {"InputField", "CheckBox", "Table", "ChoiceField", "RadioButton", "ListBox"} else ""
    pages: tuple[PageInfo, ...] = ()
    if control_type == "Table":
        children = tuple(extract_table_columns(candidate, data_path))
    elif control_type == "Panel":
        pages, children = decode_panel_pages(candidate, nested_children)
    else:
        children = tuple(nested_children)
    return ControlInfo(
        source_id=candidate[1],
        name=name,
        type=control_type,
        data_path=data_path,
        events=tuple(extract_events(candidate, control_type, lexical_name, event_map)),
        lexical_name=lexical_name,
        children=children,
        pages=pages,
    )


def decode_panel_pages(
    candidate: list[object],
    children: list[ControlInfo],
) -> tuple[tuple[PageInfo, ...], tuple[ControlInfo, ...]]:
    """Decode panel pages and exact child membership from the layout profile."""
    page_names = panel_page_names(candidate)
    if not page_names:
        return (), tuple(children)
    page_by_source_id: dict[str, int] = {}
    if len(candidate) > 5 and isinstance(candidate[5], list):
        for child_record in candidate[5]:
            if not is_control_record(child_record):
                continue
            page_index = control_page_index(child_record, len(page_names))
            if page_index is not None:
                page_by_source_id[child_record[1]] = page_index
    grouped: list[list[ControlInfo]] = [[] for _ in page_names]
    direct: list[ControlInfo] = []
    for child in children:
        page_index = page_by_source_id.get(child.source_id)
        if page_index is None:
            direct.append(child)
        else:
            grouped[page_index].append(child)
    pages = tuple(PageInfo(name, tuple(grouped[index])) for index, name in enumerate(page_names))
    return pages, tuple(direct)


def panel_page_names(candidate: list[object]) -> tuple[str, ...]:
    if len(candidate) <= 2 or not isinstance(candidate[2], list) or len(candidate[2]) <= 1:
        return ()
    profile = candidate[2][1]
    if not isinstance(profile, list):
        return ()
    for record in profile:
        if not isinstance(record, list) or len(record) < 3 or record[0] != "1":
            continue
        if not isinstance(record[1], str) or not record[1].isdigit() or int(record[1]) != len(record) - 2:
            continue
        names: list[str] = []
        for descriptor in record[2:]:
            if not isinstance(descriptor, list) or len(descriptor) <= 6 or descriptor[0] != "3":
                names = []
                break
            if not isinstance(descriptor[6], str) or not descriptor[6]:
                names = []
                break
            names.append(descriptor[6])
        if names:
            return tuple(names)
    return ()


def control_page_index(candidate: list[object], page_count: int) -> int | None:
    if len(candidate) <= 3 or not isinstance(candidate[3], list) or len(candidate[3]) <= 18:
        return None
    value = candidate[3][18]
    if not isinstance(value, str) or not value.isdigit():
        return None
    page_index = int(value)
    return page_index if page_index < page_count else None


def control_metadata_name(candidate: list[object]) -> str:
    for value in walk_owned_lists(candidate):
        if len(value) >= 2 and value[0] == "14" and isinstance(value[1], str) and value[1]:
            return value[1]
    return ""


def extract_table_columns(table_record: list[object], table_path: str) -> list[ControlInfo]:
    if len(table_record) < 3 or not isinstance(table_record[2], list):
        return []
    info = table_record[2]
    if len(info) < 3 or not isinstance(info[2], list) or len(info[2]) < 2 or not isinstance(info[2][1], list):
        return []
    view = info[2][1]
    if len(view) < 24 or not isinstance(view[23], list):
        return []
    columns: list[ControlInfo] = []
    for ordinal, column in enumerate(view[23][1:]):
        body = column_body(column)
        if body is None or len(body) < 31 or not isinstance(body[30], str) or not body[30]:
            continue
        name = body[30]
        columns.append(
            ControlInfo(
                source_id=f"{table_record[1]}:{ordinal}",
                name=name,
                type="InputField",
                data_path=f"{table_path}.{name}" if table_path else name,
                events=(),
                lexical_name=name,
                is_column=True,
            )
        )
    return columns


def column_body(column: object) -> list[object] | None:
    if not isinstance(column, list) or len(column) < 2 or not isinstance(column[1], list):
        return None
    wrapper = column[1]
    if len(wrapper) < 2 or not isinstance(wrapper[1], list):
        return None
    envelope = wrapper[1]
    if len(envelope) < 2 or not isinstance(envelope[1], list):
        return None
    return envelope[1]


def extract_form_events(
    form_root: object,
    event_map: dict[tuple[str, str], EventMapping] | None = None,
) -> list[EventInfo]:
    if not isinstance(form_root, list) or len(form_root) <= 4 or not isinstance(form_root[4], list):
        return []
    return extract_events(form_root[4], "Form", "", event_map or {})


def extract_command_bar_actions(form_root: object) -> list[CommandInfo]:
    """Read explicit BSL actions and their button names from command bars."""
    commands: list[CommandInfo] = []
    for record in walk_lists(form_root):
        if not is_control_record(record) or CONTROL_TYPE_BY_GUID[record[0].lower()] != "CommandBar":
            continue
        if len(record) < 3 or not isinstance(record[2], list) or len(record[2]) < 2:
            continue
        info = record[2][1]
        if not isinstance(info, list) or len(info) <= 7 or not isinstance(info[7], list):
            continue
        items = info[7]
        if len(items) < 6 or items[0] != "5" or not isinstance(items[4], str) or not items[4].isdigit():
            continue
        action_end = 5 + int(items[4])
        if action_end >= len(items) or not isinstance(items[action_end], str) or not items[action_end].isdigit():
            continue
        group_end = action_end + 1 + int(items[action_end])
        if group_end > len(items):
            continue
        names_by_action: dict[str, list[str]] = {}
        for group in items[action_end + 1:group_end]:
            if not isinstance(group, list) or len(group) < 5 or group[0] != "5":
                continue
            if not isinstance(group[4], str) or not group[4].isdigit():
                continue
            for index in range(int(group[4])):
                position = 5 + index * 2
                if position + 1 >= len(group):
                    break
                action_id, button = group[position:position + 2]
                if isinstance(action_id, str) and isinstance(button, list) and len(button) > 1:
                    if isinstance(button[1], str) and button[1]:
                        names_by_action.setdefault(action_id, []).append(button[1])
        bar_name = control_metadata_name(record)
        for action in items[5:action_end]:
            if not isinstance(action, list) or len(action) < 5 or not isinstance(action[1], str):
                continue
            payload = action[4]
            if not isinstance(payload, list) or len(payload) < 2 or payload[0] != "3":
                continue
            handler = payload[1]
            if not isinstance(handler, str) or not handler or is_uuid(handler):
                continue
            for button_name in dict.fromkeys(names_by_action.get(action[1], [handler])):
                name = f"{bar_name}.{button_name}" if bar_name else button_name
                commands.append(CommandInfo(name=name, handler=handler, source_id=action[1]))
    return commands


def extract_page_name(form_root: object) -> str:
    if not isinstance(form_root, list) or len(form_root) < 2 or not isinstance(form_root[1], list):
        return ""
    control_section = form_root[1]
    if len(control_section) < 2 or not isinstance(control_section[1], list) or not control_section[1]:
        return ""
    page = control_section[1][0]
    if not isinstance(page, list) or len(page) < 3 or not isinstance(page[2], list) or len(page[2]) < 2:
        return ""
    return page[2][1] if page[2][0] == "ru" and isinstance(page[2][1], str) else ""


def extract_events(
    value: object,
    control_type: str,
    control_name: str,
    event_map: dict[tuple[str, str], EventMapping],
) -> list[EventInfo]:
    events: list[EventInfo] = []
    seen: set[tuple[str, str, str]] = set()
    for record, ancestors in walk_owned_lists_with_ancestors(value):
        event_type = event_control_type(control_type, ancestors)
        event = decode_event_record(record, event_type, control_name, event_map)
        if event is None or (event.control_type, event.source_id, event.handler) in seen:
            continue
        seen.add((event.control_type, event.source_id, event.handler))
        events.append(event)
    return events


def event_control_type(control_type: str, ancestors: tuple[list[object], ...]) -> str:
    if control_type != "Table":
        return control_type
    for ancestor in reversed(ancestors):
        if not ancestor or not isinstance(ancestor[0], str):
            continue
        guid = ancestor[0].lower()
        if guid in TABLE_EVENT_SCOPE_GUIDS:
            return f"Table@{guid}"
    return control_type


def decode_event_record(
    record: list[object],
    control_type: str,
    control_name: str,
    event_map: dict[tuple[str, str], EventMapping],
) -> EventInfo | None:
    if (
        len(record) < 3
        or not isinstance(record[0], str)
        or not record[0].lstrip("-").isdigit()
        or not isinstance(record[1], str)
        or not is_uuid(record[1])
    ):
        return None
    payload = record[2]
    if not isinstance(payload, list) or len(payload) < 2 or payload[0] != "3" or not isinstance(payload[1], str) or not payload[1]:
        return None
    name, resolution = resolve_event_name(event_map, control_type, record[0])
    lexical_name = handler_event_suffix(control_type, payload[1])
    if resolution == "unresolved" and lexical_name:
        name, resolution = lexical_name, "lexical"
    elif control_type == "Table" and lexical_name and lexical_name != name:
        # Table event IDs can be reused by distinct table subtypes.  A known
        # exact suffix in the handler is stronger evidence for this collision.
        name, resolution = lexical_name, f"{resolution}+lexical-conflict"
    return EventInfo(
        source_id=record[0], control_type=control_type, name=name, handler=payload[1], resolution=resolution,
    )


def resolve_event_name(
    event_map: dict[tuple[str, str], EventMapping],
    control_type: str,
    source_id: str,
) -> tuple[str, str]:
    mapping = event_map.get((control_type, source_id))
    if mapping:
        return mapping.event_name, mapping.source
    platform_name = PLATFORM_EVENT_NAMES.get((control_type, source_id))
    if platform_name:
        return platform_name, "platform"
    return (f"UnknownEvent_{source_id}" if source_id else "UnknownEvent"), "unresolved"


@functools.cache
def known_event_names(control_type: str) -> tuple[str, ...]:
    return tuple(sorted(load_event_vocabulary().get(control_type, set()), key=len, reverse=True))


def handler_event_suffix(control_type: str, handler: str) -> str:
    return next((name for name in known_event_names(control_type) if handler.casefold().endswith(name.casefold())), "")


def write_rlm_form(
    form_root: object,
    module: bytes,
    output: Path,
    event_map: dict[tuple[str, str], EventMapping] | None = None,
) -> dict[str, int]:
    mappings = event_map or {}
    ET.register_namespace("", RLM_NAMESPACE)
    root = ET.Element(xml_name("Form"))
    form_events = extract_form_events(form_root, mappings)
    if form_events:
        append_events(root, form_events)
    attributes = extract_attributes(form_root)
    if attributes:
        attributes_node = ET.SubElement(root, xml_name("Attributes"))
        for attribute in attributes:
            item = ET.SubElement(attributes_node, xml_name("Attribute"), {"name": attribute.name})
            type_node = ET.SubElement(item, xml_name("Type"))
            for type_name in attribute.types:
                ET.SubElement(type_node, xml_name("Type")).text = type_name
    controls = extract_controls(form_root, mappings)
    if controls:
        children = ET.SubElement(root, xml_name("ChildItems"))
        page_name = extract_page_name(form_root)
        if page_name:
            page = ET.SubElement(children, xml_name("Page"), {"name": page_name})
            children = ET.SubElement(page, xml_name("ChildItems"))
        for control in controls:
            append_control(children, control)
    commands = extract_command_bar_actions(form_root)
    if commands:
        commands_node = ET.SubElement(root, xml_name("Commands"))
        for command in commands:
            item = ET.SubElement(commands_node, xml_name("Command"), {"name": command.name, "sourceId": command.source_id})
            ET.SubElement(item, xml_name("Action")).text = command.handler
    output.mkdir(parents=True, exist_ok=True)
    ET.indent(root, space="  ")
    ET.ElementTree(root).write(output / "Form.xml", encoding="utf-8", xml_declaration=True)
    module_dir = output / "Form"
    module_dir.mkdir(exist_ok=True)
    (module_dir / "Module.bsl").write_bytes(module)
    return {
        "attributes": len(attributes),
        "controls": control_count(controls),
        "tables": sum(1 for control in flatten_controls(controls) if control.type == "Table"),
        "columns": column_count(controls),
        "handlers": event_count(controls) + len(form_events) + len(commands),
        "commands": len(commands),
    }


def append_events(parent: ET.Element, events: tuple[EventInfo, ...] | list[EventInfo]) -> None:
    if not events:
        return
    events_node = ET.SubElement(parent, xml_name("Events"))
    for event in events:
        node = ET.SubElement(events_node, xml_name("Event"), {"name": event.name, "sourceId": event.source_id, "resolution": event.resolution})
        node.text = event.handler


def append_control(parent: ET.Element, control: ControlInfo) -> None:
    item = ET.SubElement(parent, xml_name(control.type), {"name": control.name, "sourceId": control.source_id})
    if control.data_path:
        ET.SubElement(item, xml_name("DataPath")).text = control.data_path
    append_events(item, control.events)
    if control.pages:
        pages = ET.SubElement(item, xml_name("Pages"))
        for page_info in control.pages:
            page = ET.SubElement(pages, xml_name("Page"), {"name": page_info.name})
            if page_info.children:
                page_children = ET.SubElement(page, xml_name("ChildItems"))
                for child in page_info.children:
                    append_control(page_children, child)
    if control.children:
        children = ET.SubElement(item, xml_name("ChildItems"))
        for child in control.children:
            append_control(children, child)


def control_count(controls: tuple[ControlInfo, ...] | list[ControlInfo]) -> int:
    return sum((0 if control.is_column else 1) + control_count(nested_controls(control)) for control in controls)


def column_count(controls: tuple[ControlInfo, ...] | list[ControlInfo]) -> int:
    return sum((1 if control.is_column else 0) + column_count(nested_controls(control)) for control in controls)


def flatten_controls(controls: tuple[ControlInfo, ...] | list[ControlInfo]):
    for control in controls:
        yield control
        yield from flatten_controls(nested_controls(control))


def event_count(controls: tuple[ControlInfo, ...] | list[ControlInfo]) -> int:
    return sum(len(control.events) + event_count(nested_controls(control)) for control in controls)


def nested_controls(control: ControlInfo) -> tuple[ControlInfo, ...]:
    return control.children + tuple(child for page in control.pages for child in page.children)


def xml_name(local_name: str) -> str:
    return f"{{{RLM_NAMESPACE}}}{local_name}"


def read_streams(form_bin: bytes) -> dict[str, Stream]:
    """Read named streams from a 1C file container.

    The container begins with four little-endian integers. Its directory and
    every file are documents stored in one or more blocks. A block header is a
    CRLF-delimited line of three hexadecimal values: total document size,
    bytes stored in this block, and the offset of the next block.
    """
    if len(form_bin) < HEADER_BYTES:
        raise ValueError("Form.bin is shorter than the container header")
    end, block_size, file_count, reserved = struct.unpack_from("<4i", form_bin)
    if end != CHAIN_END or block_size <= 0 or file_count < 0 or reserved != 0:
        raise ValueError("Unsupported Form.bin container header")

    directory = read_document(form_bin, HEADER_BYTES)
    if len(directory) < file_count * 12:
        raise ValueError("Truncated Form.bin file directory")

    streams: dict[str, Stream] = {}
    for index in range(file_count):
        descriptor_at, payload_at, marker = struct.unpack_from("<3i", directory, index * 12)
        if marker != CHAIN_END:
            raise ValueError(f"Invalid directory marker for stream #{index}")
        descriptor = read_document(form_bin, descriptor_at)
        name = decode_stream_name(descriptor)
        streams[name] = Stream(name=name, payload=read_document(form_bin, payload_at))
    return streams


def read_document(container: bytes, first_block: int) -> bytes:
    """Follow a linked document block chain and return its declared bytes."""
    pieces: list[bytes] = []
    expected_size: int | None = None
    offset = first_block
    visited: set[int] = set()
    while True:
        if offset in visited:
            raise ValueError(f"Cyclic Form.bin block chain at offset {offset}")
        visited.add(offset)
        total, stored, next_block, payload_start = read_block_header(container, offset)
        if expected_size is None:
            expected_size = total
        payload_end = payload_start + stored
        if payload_end > len(container):
            raise ValueError(f"Form.bin block at {offset} exceeds container length")
        pieces.append(container[payload_start:payload_end])
        if next_block == CHAIN_END:
            break
        if next_block < HEADER_BYTES or next_block >= len(container):
            raise ValueError(f"Invalid next Form.bin block offset {next_block}")
        offset = next_block
    return b"".join(pieces)[: expected_size or 0]


def read_block_header(container: bytes, offset: int) -> tuple[int, int, int, int]:
    if container[offset : offset + 2] != b"\r\n":
        raise ValueError(f"Expected block header at offset {offset}")
    line_end = container.find(b"\r\n", offset + 2)
    if line_end < 0:
        raise ValueError(f"Unterminated block header at offset {offset}")
    try:
        total_text, stored_text, next_text = container[offset + 2 : line_end].decode("ascii").split()
        total, stored, next_block = int(total_text, 16), int(stored_text, 16), int(next_text, 16)
    except (UnicodeDecodeError, ValueError) as error:
        raise ValueError(f"Malformed block header at offset {offset}") from error
    if total < 0 or stored < 0:
        raise ValueError(f"Negative size in block header at offset {offset}")
    return total, stored, next_block, line_end + 2


def decode_stream_name(descriptor: bytes) -> str:
    """Decode the UTF-16LE name after a descriptor's timestamps and flags."""
    if len(descriptor) < 24:
        raise ValueError("Truncated Form.bin stream descriptor")
    flags = struct.unpack_from("<i", descriptor, 16)[0]
    if flags != 0:
        raise ValueError(f"Unsupported stream descriptor flags: {flags}")
    try:
        name = descriptor[20:].decode("utf-16le").partition("\0")[0]
    except UnicodeDecodeError as error:
        raise ValueError("Invalid UTF-16LE stream name") from error
    if not name:
        raise ValueError("Empty Form.bin stream name")
    return name


def convert_form_bin(
    form_bin: Path,
    output: Path,
    event_map: dict[tuple[str, str], EventMapping] | None = None,
) -> dict[str, int]:
    streams = read_streams(form_bin.read_bytes())
    required = {"form", "module"}
    missing = required - streams.keys()
    if missing:
        raise ValueError(f"Form.bin misses required streams: {', '.join(sorted(missing))}")
    form_root = parse_bracket_stream(streams["form"].payload)
    return write_rlm_form(form_root, streams["module"].payload, output, event_map)


def is_current(form_bin: Path, output: Path) -> bool:
    form_xml = output / "Form.xml"
    module = output / "Form" / "Module.bsl"
    if not form_xml.is_file() or not module.is_file():
        return False
    source_mtime = max(form_bin.stat().st_mtime, Path(__file__).stat().st_mtime)
    return min(form_xml.stat().st_mtime, module.stat().st_mtime) >= source_mtime


def changed_files_in_git(source: Path) -> set[Path] | None:
    """Return changed paths from the enclosing repository, if there is one."""
    root = subprocess.run(
        ["git", "-C", str(source), "rev-parse", "--show-toplevel"],
        capture_output=True,
        text=True,
        check=False,
    )
    if root.returncode != 0:
        return None
    repository = Path(root.stdout.strip())
    status = subprocess.run(
        ["git", "-C", str(repository), "status", "--porcelain=v1", "-z", "--untracked-files=all"],
        capture_output=True,
        check=False,
    )
    if status.returncode != 0:
        return None
    paths: set[Path] = set()
    for record in status.stdout.decode(errors="replace").split("\0"):
        if len(record) >= 4:
            paths.add(repository / record[3:].replace("/", "\\"))
    return paths


def _write_json_atomic(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    temporary.replace(path)


def _event_paths(project_root: Path) -> tuple[Path, Path]:
    directory = project_root / EVENT_DIRECTORY
    return directory / EVENT_MAP_FILE, directory / UNRESOLVED_EVENTS_FILE


def _voting_policy() -> dict[str, object]:
    return {
        "unanimous": "принимается при любом ненулевом количестве допустимых голосов",
        "minimum_votes": STATISTICAL_MIN_VOTES,
        "minimum_ratio": STATISTICAL_MIN_RATIO,
        "minimum_forms": STATISTICAL_MIN_FORMS,
        "control_vote": "direct, известный или общий суффикс, нормализованный по словарю событий типа элемента",
        "form_vote": "полное имя обработчика должно входить в словарь событий формы",
        "procedure_required": True,
        "mixed_semantics_blocks_mapping": True,
    }


def load_event_map(project_root: Path) -> dict[tuple[str, str], EventMapping]:
    map_path, _ = _event_paths(project_root)
    if not map_path.is_file():
        return {}
    payload = json.loads(map_path.read_text(encoding="utf-8-sig"))
    if payload.get("schema_version") != EVENT_SCHEMA_VERSION or not isinstance(payload.get("mappings"), dict):
        raise ValueError(f"Unsupported ordinary event map: {map_path}")
    result: dict[tuple[str, str], EventMapping] = {}
    for control_type, values in payload["mappings"].items():
        if not isinstance(control_type, str) or not isinstance(values, dict):
            raise ValueError(f"Malformed ordinary event map: {map_path}")
        for source_id, entry in values.items():
            if not isinstance(source_id, str) or not isinstance(entry, dict):
                raise ValueError(f"Malformed ordinary event map: {map_path}")
            event_name = entry.get("event_name")
            source = entry.get("source", "manual")
            if not isinstance(event_name, str) or not event_name or not isinstance(source, str):
                raise ValueError(f"Malformed ordinary event map: {map_path}")
            result[(control_type, source_id)] = EventMapping(event_name, source)
    return result


def _manual_resolutions(project_root: Path) -> dict[tuple[str, str], EventMapping]:
    _, unresolved_path = _event_paths(project_root)
    if not unresolved_path.is_file():
        return {}
    payload = json.loads(unresolved_path.read_text(encoding="utf-8-sig"))
    events = payload.get("events", [])
    if not isinstance(events, list):
        raise ValueError(f"Malformed unresolved event file: {unresolved_path}")
    result: dict[tuple[str, str], EventMapping] = {}
    for entry in events:
        if not isinstance(entry, dict):
            raise ValueError(f"Malformed unresolved event file: {unresolved_path}")
        event_name = entry.get("event_name", "")
        if not event_name:
            continue
        control_type, source_id = entry.get("control_type"), entry.get("source_id")
        if not isinstance(control_type, str) or not isinstance(source_id, str) or not isinstance(event_name, str):
            raise ValueError(f"Malformed manual event resolution: {unresolved_path}")
        key = (control_type, source_id)
        previous = result.get(key)
        if previous and previous.event_name != event_name:
            raise ValueError(f"Conflicting manual event names for {control_type}/{source_id}")
        result[key] = EventMapping(event_name, "manual")
    return result


METADATA_KIND_NAMES = {
    "Catalogs": "Справочник",
    "Documents": "Документ",
    "Reports": "Отчет",
    "DataProcessors": "Обработка",
    "ChartsOfCharacteristicTypes": "ПланВидовХарактеристик",
    "ChartsOfAccounts": "ПланСчетов",
    "ChartsOfCalculationTypes": "ПланВидовРасчета",
    "InformationRegisters": "РегистрСведений",
    "AccumulationRegisters": "РегистрНакопления",
    "AccountingRegisters": "РегистрБухгалтерии",
    "CalculationRegisters": "РегистрРасчета",
    "BusinessProcesses": "БизнесПроцесс",
    "Tasks": "Задача",
}


def metadata_path(form_bin: Path, configuration_root: Path) -> str:
    parts = form_bin.relative_to(configuration_root).parts
    if len(parts) >= 6 and parts[2] == "Forms":
        kind = METADATA_KIND_NAMES.get(parts[0], parts[0])
        return f"{kind}.{parts[1]}.Форма.{parts[3]}"
    return ".".join(parts[:-1])


def procedure_signature(module: bytes, handler: str) -> str:
    text = module.decode("utf-8-sig", errors="replace")
    pattern = re.compile(
        rf"^\s*(?:Процедура|Функция)\s+{re.escape(handler)}\s*\(",
        flags=re.IGNORECASE | re.MULTILINE,
    )
    match = pattern.search(text)
    if not match:
        return ""
    depth = 1
    quote = False
    cursor = match.end()
    while cursor < len(text):
        character = text[cursor]
        if character == '"':
            if quote and cursor + 1 < len(text) and text[cursor + 1] == '"':
                cursor += 2
                continue
            quote = not quote
        elif not quote:
            if character == "(":
                depth += 1
            elif character == ")":
                depth -= 1
                if depth == 0:
                    return re.sub(r"\s+", " ", text[match.start():cursor + 1]).strip()
        cursor += 1
    return ""


def normalize_procedure_signature(signature: str) -> str:
    if not signature:
        return ""
    opening = signature.find("(")
    closing = signature.rfind(")")
    if opening < 0 or closing < opening:
        return ""
    parameters: list[str] = []
    current: list[str] = []
    depth = 0
    quote = False
    for character in signature[opening + 1:closing] + ",":
        if character == '"':
            quote = not quote
        elif not quote:
            if character == "(":
                depth += 1
            elif character == ")":
                depth = max(0, depth - 1)
            elif character == "," and depth == 0:
                parameter = "".join(current).strip()
                current = []
                if not parameter:
                    continue
                parameter = re.split(r"=(?!=)", parameter, maxsplit=1)[0]
                parameter = re.sub(r"^\s*Знач\s+", "", parameter, flags=re.IGNORECASE)
                parameters.append(re.sub(r"\s+", "", parameter).casefold())
                continue
        current.append(character)
    return f"({','.join(parameters)})"


def collect_event_observations(
    form_bins: list[Path],
    configuration_root: Path,
    project_root: Path,
) -> list[EventObservation]:
    observations: list[EventObservation] = []
    for form_bin in form_bins:
        streams = read_streams(form_bin.read_bytes())
        required = {"form", "module"}
        missing = required - streams.keys()
        if missing:
            raise ValueError(f"Form.bin misses required streams: {', '.join(sorted(missing))}: {form_bin}")
        form_root = parse_bracket_stream(streams["form"].payload)
        relative = form_bin.relative_to(project_root).as_posix()
        module_path = (form_bin.parent / "Form" / "Module.bsl").relative_to(project_root).as_posix()
        display_path = metadata_path(form_bin, configuration_root)
        module = streams["module"].payload
        for event in extract_form_events(form_root):
            observations.append(
                EventObservation(
                    "Form", "", event.source_id, event.handler, display_path, relative, module_path,
                    procedure_signature(module, event.handler),
                )
            )
        for control in flatten_controls(extract_controls(form_root)):
            for event in control.events:
                observations.append(
                    EventObservation(
                        event.control_type, control.lexical_name, event.source_id, event.handler, display_path,
                        relative, module_path, procedure_signature(module, event.handler),
                    )
                )
    return observations


def _direct_candidate(observation: EventObservation) -> str:
    if observation.control_type == "Form":
        return observation.handler
    if observation.control_name and observation.handler.casefold().startswith(observation.control_name.casefold()):
        return observation.handler[len(observation.control_name):]
    return ""


def _known_suffix_candidate(handler: str, known_event_names: set[str]) -> str:
    matches = [name for name in known_event_names if handler.casefold().endswith(name.casefold())]
    return max(matches, key=len) if matches else ""


def load_event_vocabulary() -> dict[str, set[str]]:
    """Load the ordinary-form event vocabulary shipped with the parser."""
    try:
        if __package__:
            payload = resources.files(__package__).joinpath(EVENT_VOCABULARY_FILE).read_text(encoding="utf-8")
        else:
            payload = Path(__file__).with_name(EVENT_VOCABULARY_FILE).read_text(encoding="utf-8")
        document = json.loads(payload)
    except (FileNotFoundError, OSError, TypeError, ValueError, json.JSONDecodeError) as error:
        raise RuntimeError(f"Cannot load {EVENT_VOCABULARY_FILE}: {error}") from error
    raw = document.get("events_by_control")
    if document.get("schema_version") != 1 or not isinstance(raw, dict):
        raise RuntimeError(f"Invalid {EVENT_VOCABULARY_FILE}")
    return {
        str(control_type): {str(name) for name in names if isinstance(name, str) and name}
        for control_type, names in raw.items()
        if isinstance(names, list)
    }


_IDENTIFIER_WORDS = re.compile(
    r"[A-ZА-ЯЁ]+(?=[A-ZА-ЯЁ][a-zа-яё]|\d|$)|[A-ZА-ЯЁ]?[a-zа-яё]+|\d+",
)


def _identifier_words(value: str) -> list[str]:
    return _IDENTIFIER_WORDS.findall(value.replace("_", " "))


def infer_suffix_candidates(observations: list[EventObservation]) -> dict[str, str]:
    """Return handler -> longest token suffix shared by at least two different handlers."""
    handlers = {item.handler.casefold(): item.handler for item in observations}
    tokenized = {key: _identifier_words(value) for key, value in handlers.items()}
    shared: dict[str, tuple[str, ...]] = {}
    keys = sorted(handlers)
    for index, left_key in enumerate(keys):
        left = tokenized[left_key]
        for right_key in keys[index + 1:]:
            right = tokenized[right_key]
            length = 0
            while length < min(len(left), len(right)) and left[-length - 1].casefold() == right[-length - 1].casefold():
                length += 1
            if not length:
                continue
            words = tuple(left[-length:])
            candidate = "".join(words)
            if candidate and not candidate[0].isdigit():
                shared.setdefault(candidate.casefold(), words)
    result: dict[str, str] = {}
    for handler_key, words in tokenized.items():
        matches = [
            suffix_words
            for suffix_words in shared.values()
            if len(suffix_words) <= len(words)
            and [word.casefold() for word in words[-len(suffix_words):]] == [word.casefold() for word in suffix_words]
        ]
        if matches:
            result[handler_key] = "".join(max(matches, key=lambda value: (len(value), len("".join(value)))))
    return result


def _occurrence(observation: EventObservation) -> dict[str, str]:
    return {
        "metadata_path": observation.metadata_path,
        "source_path": observation.source_path,
        "module_path": observation.module_path,
        "control_type": observation.control_type,
        "control_name": observation.control_name,
        "handler": observation.handler,
        "procedure_signature": observation.procedure_signature,
    }


def infer_event_mappings(
    observations: list[EventObservation],
    manual: dict[tuple[str, str], EventMapping],
    known_event_names: set[str] | None = None,
) -> tuple[
    dict[tuple[str, str], EventMapping],
    dict[str, object],
    list[dict[str, object]],
    list[dict[str, object]],
    list[dict[str, object]],
]:
    by_key: dict[tuple[str, str], list[EventObservation]] = defaultdict(list)
    for observation in observations:
        by_key[(observation.control_type, observation.source_id)].append(observation)

    vocabulary = load_event_vocabulary()
    additional_known_names = set(known_event_names or set())
    proposals: dict[tuple[str, str], tuple[str, dict[str, object]]] = {}
    unresolved: list[dict[str, object]] = []
    outliers: list[dict[str, object]] = []
    ignored_groups: list[dict[str, object]] = []
    mixed_keys: set[tuple[str, str]] = set()
    group_evidence: dict[tuple[str, str], dict[str, object]] = {}
    for key, items in sorted(by_key.items()):
        usable = [item for item in items if item.procedure_signature]
        ignored = [item for item in items if not item.procedure_signature]
        if not usable:
            ignored_groups.append(
                {
                    "control_type": key[0],
                    "source_id": key[1],
                    "observations": len(items),
                    "ignored_no_procedure": len(ignored),
                }
            )
            continue
        candidates: Counter[str] = Counter()
        candidate_items: dict[str, list[EventObservation]] = defaultdict(list)
        source_candidates: dict[str, Counter[str]] = {
            "direct": Counter(),
            "known_suffix": Counter(),
            "inferred_suffix": Counter(),
        }
        excluded: list[EventObservation] = []
        base_control_type = key[0].partition("@")[0]
        group_known_names = set(vocabulary.get(base_control_type, set()))
        group_known_names.update(
            mapping.event_name
            for (control_type, _), mapping in manual.items()
            if control_type == key[0]
        )
        group_known_names.update(additional_known_names)
        raw_direct_by_item = {id(item): _direct_candidate(item) for item in usable}
        direct_by_item = {
            id(item): _known_suffix_candidate(raw_direct_by_item[id(item)], group_known_names)
            for item in usable
        }
        known_by_item = {
            id(item): _known_suffix_candidate(item.handler, group_known_names)
            for item in usable
            if not direct_by_item[id(item)]
        }
        inferable = [
            item
            for item in usable
            if not direct_by_item[id(item)] and not known_by_item.get(id(item), "")
        ]
        suffixes = infer_suffix_candidates(inferable)
        for item in usable:
            candidate = direct_by_item[id(item)]
            source = "direct"
            if not candidate:
                candidate = known_by_item.get(id(item), "")
                source = "known_suffix"
            if not candidate:
                candidate = _known_suffix_candidate(
                    suffixes.get(item.handler.casefold(), ""),
                    group_known_names,
                )
                source = "inferred_suffix"
            if not candidate:
                excluded.append(item)
                continue
            candidates[candidate] += 1
            candidate_items[candidate].append(item)
            source_candidates[source][candidate] += 1
        eligible_votes = sum(candidates.values())
        winner, winning_votes = candidates.most_common(1)[0] if candidates else ("", 0)
        confidence = winning_votes / eligible_votes if eligible_votes else 0.0
        winning_items = candidate_items.get(winner, [])
        distinct_forms = len({item.source_path for item in winning_items})
        distinct_controls = len(
            {(item.source_path, item.control_name) for item in winning_items if item.control_name}
        )
        accepted_name = manual.get(key).event_name if key in manual else ""
        conflict = bool(accepted_name and winner and winner != accepted_name)
        signature_clusters = Counter(normalize_procedure_signature(item.procedure_signature) for item in usable)
        signature_clusters.pop("", None)
        stable_candidates = {
            name
            for name, values in candidate_items.items()
            if len(values) >= 3 and len({item.source_path for item in values}) >= 2
        }
        significant_signatures = {name for name, count in signature_clusters.items() if count >= 2}
        mixed_reasons: list[str] = []
        if len(stable_candidates) >= 2 and len(significant_signatures) >= 2:
            mixed_reasons.extend(("multiple_stable_suffixes", "different_signature_clusters"))
        direct_names = source_candidates["direct"]
        if len(direct_names) >= 3 and len(signature_clusters) >= 2 and len(usable) <= 20:
            mixed_reasons.extend(("conflicting_direct_candidates", "different_signature_clusters"))
        stable_known = [
            name
            for name, count in source_candidates["known_suffix"].items()
            if count >= 3 and len({item.source_path for item in candidate_items[name]}) >= 2
        ]
        if len(stable_known) >= 2:
            mixed_reasons.append("multiple_known_suffixes")
        mixed_reasons = list(dict.fromkeys(mixed_reasons))
        mixed_semantics = bool(mixed_reasons)
        if mixed_semantics:
            mixed_keys.add(key)
        unanimous = len(candidates) == 1
        threshold_majority = (
            bool(winner)
            and winning_votes >= STATISTICAL_MIN_VOTES
            and confidence >= STATISTICAL_MIN_RATIO
            and distinct_forms >= STATISTICAL_MIN_FORMS
        )
        statistically_safe = bool(winner) and (unanimous or threshold_majority) and not conflict and not mixed_semantics
        evidence: dict[str, object] = {
            "observations": len(items),
            "usable_observations": len(usable),
            "ignored_no_procedure": len(ignored),
            "eligible_votes": eligible_votes,
            "excluded_observations": len(excluded),
            "winning_votes": winning_votes,
            "confidence": round(confidence, 6),
            "distinct_forms": distinct_forms,
            "distinct_controls": distinct_controls,
            "candidate_names": dict(sorted(candidates.items())),
            "raw_direct_candidates": dict(sorted(Counter(
                name for name in raw_direct_by_item.values() if name
            ).items())),
            "direct_candidates": dict(sorted(source_candidates["direct"].items())),
            "known_suffix_candidates": dict(sorted(source_candidates["known_suffix"].items())),
            "suffix_candidates": dict(sorted(source_candidates["inferred_suffix"].items())),
            "signature_clusters": dict(sorted(signature_clusters.items())),
            "mixed_semantics": mixed_semantics,
            "mixed_semantics_reasons": mixed_reasons,
            "decision": "unanimous" if unanimous else "threshold_majority",
            "thresholds": _voting_policy(),
        }
        group_evidence[key] = evidence
        if statistically_safe:
            proposals[key] = (winner, evidence)
            minority = [item for name, values in candidate_items.items() if name != winner for item in values]
            if minority:
                outliers.append(
                    {
                        "control_type": key[0],
                        "source_id": key[1],
                        "accepted_event_name": winner,
                        **evidence,
                        "minority_occurrences": [_occurrence(item) for item in minority],
                    }
                )
        if (key not in manual and not statistically_safe) or mixed_semantics:
            unresolved.append(
                {
                    "control_type": key[0],
                    "source_id": key[1],
                    "event_name": accepted_name if mixed_semantics else "",
                    "status": "manual_with_mixed_semantics" if accepted_name and mixed_semantics else "unresolved",
                    **evidence,
                    "winning_candidate": winner,
                    "occurrences": [_occurrence(item) for item in items],
                }
            )
        elif conflict:
            unresolved.append(
                {
                    "control_type": key[0],
                    "source_id": key[1],
                    "event_name": "",
                    **evidence,
                    "conflict_with_mapping": accepted_name,
                    "occurrences": [_occurrence(item) for item in items],
                }
            )

    candidate_keys: dict[tuple[str, str], list[tuple[str, str]]] = defaultdict(list)
    for key, mapping in manual.items():
        candidate_keys[(key[0], mapping.event_name)].append(key)
    for key, (candidate, _) in proposals.items():
        candidate_keys[(key[0], candidate)].append(key)
    conflicting_keys: set[tuple[str, str]] = set()
    for keys in candidate_keys.values():
        unique_keys = set(keys)
        proposal_keys = [key for key in unique_keys if key in proposals]
        manual_keys = {key for key in unique_keys if key in manual}
        if manual_keys:
            conflicting_keys.update(key for key in proposal_keys if key not in manual_keys)
            continue
        if len(proposal_keys) <= 1:
            continue
        scores = {
            key: (
                int(proposals[key][1]["winning_votes"]),
                int(proposals[key][1]["distinct_forms"]),
                float(proposals[key][1]["confidence"]),
            )
            for key in proposal_keys
        }
        best_score = max(scores.values())
        strongest = [key for key, score in scores.items() if score == best_score]
        if len(strongest) == 1:
            conflicting_keys.update(key for key in proposal_keys if key != strongest[0])
        else:
            conflicting_keys.update(proposal_keys)
    outliers = [
        item
        for item in outliers
        if (str(item["control_type"]), str(item["source_id"])) not in conflicting_keys
    ]
    event_map = {key: mapping for key, mapping in manual.items() if key not in mixed_keys}
    details: dict[str, dict[str, object]] = defaultdict(dict)
    for key, mapping in manual.items():
        if key in mixed_keys:
            continue
        entry: dict[str, object] = {"event_name": mapping.event_name, "source": "manual"}
        if key in group_evidence:
            entry["evidence"] = group_evidence[key]
        details[key[0]][key[1]] = entry
    for key, (candidate, evidence) in proposals.items():
        if key in conflicting_keys or key in manual:
            continue
        event_map[key] = EventMapping(candidate, "statistics")
        details[key[0]][key[1]] = {
            "event_name": candidate,
            "source": "statistics",
            "evidence": evidence,
        }
    for key in sorted(conflicting_keys):
        candidate, evidence = proposals[key]
        items = by_key[key]
        unresolved.append(
            {
                "control_type": key[0],
                "source_id": key[1],
                "event_name": "",
                "observations": len(items),
                "candidate_names": evidence["candidate_names"],
                "conflict": "одно имя события предложено для нескольких ID; выбран более сильный кандидат или требуется ручная проверка",
                "occurrences": [_occurrence(item) for item in items],
            }
        )
    return event_map, dict(details), unresolved, outliers, ignored_groups


def prepare_event_mapping(
    project_root: Path,
    configuration_root: Path,
    *,
    force_analysis: bool = False,
    probe_paths: list[Path] | None = None,
) -> EventAnalysisResult:
    map_path, unresolved_path = _event_paths(project_root)
    existing = load_event_map(project_root)
    manual = {key: value for key, value in existing.items() if value.source == "manual"}
    resolutions = _manual_resolutions(project_root)
    for key, value in resolutions.items():
        previous = manual.get(key)
        if previous and previous.event_name != value.event_name:
            raise ValueError(f"Manual event resolution conflicts with event map: {key[0]}/{key[1]}")
        manual[key] = value
    must_analyze = force_analysis or not map_path.is_file() or bool(resolutions)
    if map_path.is_file() and not must_analyze:
        payload = json.loads(map_path.read_text(encoding="utf-8-sig"))
        must_analyze = payload.get("analyzer_version") != EVENT_ANALYZER_VERSION
    if not must_analyze and probe_paths:
        observations = collect_event_observations(probe_paths, configuration_root, project_root)
        must_analyze = any((item.control_type, item.source_id) not in existing for item in observations)
    if not must_analyze:
        return EventAnalysisResult(existing, False, 0, 0)

    form_bins = sorted(configuration_root.rglob("Form.bin"), key=lambda path: path.as_posix().casefold())
    observations = collect_event_observations(form_bins, configuration_root, project_root)
    event_map, details, unresolved, outliers, ignored_groups = infer_event_mappings(
        observations,
        manual,
    )
    accepted_sources: Counter[str] = Counter()
    for mappings in details.values():
        for entry in mappings.values():
            if entry.get("source") != "statistics" or not isinstance(entry.get("evidence"), dict):
                continue
            event_name = str(entry["event_name"])
            evidence = entry["evidence"]
            for source, field in (
                ("direct", "direct_candidates"),
                ("known_suffix", "known_suffix_candidates"),
                ("inferred_suffix", "suffix_candidates"),
            ):
                source_counts = evidence.get(field, {})
                if isinstance(source_counts, dict) and source_counts.get(event_name, 0):
                    accepted_sources[source] += 1
                    break
    analysis_summary = {
        "observations": len(observations),
        "usable_observations": sum(1 for item in observations if item.procedure_signature),
        "ignored_no_procedure": sum(1 for item in observations if not item.procedure_signature),
        "accepted_statistics": sum(accepted_sources.values()),
        "accepted_by_source": dict(sorted(accepted_sources.items())),
        "unresolved_groups": len(unresolved),
        "mixed_semantics_groups": sum(1 for entry in unresolved if entry.get("mixed_semantics")),
    }
    _write_json_atomic(
        map_path,
        {
            "schema_version": EVENT_SCHEMA_VERSION,
            "analyzer_version": EVENT_ANALYZER_VERSION,
            "voting_policy": _voting_policy(),
            "mappings": details,
        },
    )
    _write_json_atomic(
        unresolved_path,
        {
            "schema_version": EVENT_SCHEMA_VERSION,
            "analyzer_version": EVENT_ANALYZER_VERSION,
            "voting_policy": _voting_policy(),
            "instructions": "Заполните event_name после проверки события в Конфигураторе и повторите обновление.",
            "analysis_summary": analysis_summary,
            "events": unresolved,
            "statistical_outliers": outliers,
            "ignored_no_procedure_groups": ignored_groups,
        },
    )
    accepted = sum(1 for mapping in event_map.values() if mapping.source == "statistics")
    return EventAnalysisResult(event_map, True, accepted, len(unresolved))


def discover_project_root(source: Path) -> Path | None:
    start = source if source.is_dir() else source.parent
    for candidate in (start, *start.parents):
        if (candidate / "project.toml").is_file():
            return candidate
    return None


def event_context(source: Path, project_root: Path | None = None) -> tuple[Path, Path, Path | None]:
    """Keep arbitrary source trees separate from the configuration event state."""
    source = source.resolve()
    source_root = source if source.is_dir() else source.parent
    project = project_root.resolve() if project_root else discover_project_root(source)
    configuration = project / "src" / "cf" if project else None
    if configuration and configuration.is_dir() and source.is_relative_to(configuration):
        return project, configuration, None
    return source_root, source_root, project if project != source_root else None


def event_mapping_for_source(
    state_root: Path,
    scan_root: Path,
    shared_root: Path | None,
    *,
    force_analysis: bool = False,
    probe_paths: list[Path] | None = None,
) -> tuple[EventAnalysisResult, dict[tuple[str, str], EventMapping]]:
    analysis = prepare_event_mapping(
        state_root, scan_root, force_analysis=force_analysis, probe_paths=probe_paths,
    )
    shared = load_event_map(shared_root) if shared_root and _event_paths(shared_root)[0].is_file() else {}
    return analysis, {**shared, **analysis.event_map}


def convert_tree(
    source: Path,
    output: Path,
    verbose: bool,
    full: bool,
    project_root: Path | None = None,
) -> dict[str, int]:
    source = source.resolve()
    output = output.resolve()
    totals = {
        "forms_processed": 0, "forms_skipped": 0, "forms_failed": 0,
        "attributes": 0, "controls": 0, "tables": 0, "columns": 0, "handlers": 0, "commands": 0,
    }
    changed_paths = changed_files_in_git(source)
    totals["git_mode"] = changed_paths is not None
    form_bins = sorted(source.rglob("Form.bin"), key=lambda path: path.as_posix().casefold())
    state_root, scan_root, shared_root = event_context(source, project_root)
    analysis, event_map = event_mapping_for_source(
        state_root, scan_root, shared_root, force_analysis=full, probe_paths=form_bins,
    )
    totals["event_mappings"] = len(event_map)
    totals["unresolved_events"] = analysis.unresolved
    for form_bin in form_bins:
        destination = output / form_bin.relative_to(source).parent
        changed_in_git = changed_paths is not None and form_bin in changed_paths
        if not full and not analysis.rebuilt and not changed_in_git and is_current(form_bin, destination):
            totals["forms_skipped"] += 1
            if verbose:
                print(f"SKIP {form_bin}")
            continue
        try:
            summary = convert_form_bin(form_bin, destination, event_map)
        except (OSError, UnicodeError, ValueError, BracketSyntaxError) as error:
            totals["forms_failed"] += 1
            if verbose:
                print(f"ERROR {form_bin}: {error}")
            continue
        totals["forms_processed"] += 1
        for name in ("attributes", "controls", "tables", "columns", "handlers", "commands"):
            totals[name] += summary[name]
        if verbose:
            print(f"OK {form_bin} -> {destination / 'Form.xml'}")
    return totals


def main() -> None:
    parser = argparse.ArgumentParser(description="Read ordinary 1C Form.bin for RLM")
    parser.add_argument("--version", action="version", version=f"%(prog)s {SCRIPT_VERSION}")
    parser.add_argument("source", help="Path to a Form.bin or source directory")
    parser.add_argument("--output", help="Directory for extracted streams")
    parser.add_argument("--recursive", action="store_true", help="Process every Form.bin below a source directory")
    parser.add_argument("--full", action="store_true", help="Rebuild all forms, ignoring current RLM output")
    parser.add_argument("--verbose", action="store_true", help="Show one result line per form")
    parser.add_argument("--project-root", help="Project root for a shared event map; arbitrary source trees keep local state")
    parser.add_argument("--analyze-events-only", action="store_true", help="Refresh event map without writing RLM forms")
    args = parser.parse_args()
    source = Path(args.source).resolve()
    project_root = Path(args.project_root).resolve() if args.project_root else None
    if not args.output and not args.analyze_events_only:
        parser.error("--output is required unless --analyze-events-only is used")
    output = Path(args.output).resolve() if args.output else source
    state_root, scan_root, shared_root = event_context(source, project_root)
    if args.analyze_events_only:
        analysis, event_map = event_mapping_for_source(
            state_root, scan_root, shared_root, force_analysis=True,
        )
        print(
            json.dumps(
                {
                    "event_mappings": len(event_map),
                    "unresolved_events": analysis.unresolved,
                    "event_map": str(state_root / EVENT_DIRECTORY / EVENT_MAP_FILE),
                    "review": str(state_root / EVENT_DIRECTORY / UNRESOLVED_EVENTS_FILE),
                },
                ensure_ascii=False,
                indent=2,
            )
        )
        return
    if source.is_file():
        if args.recursive:
            parser.error("--recursive requires a source directory")
        analysis, event_map = event_mapping_for_source(
            state_root, scan_root, shared_root, force_analysis=args.full, probe_paths=[source],
        )
        if not args.full and not analysis.rebuilt and is_current(source, output):
            print(json.dumps({"forms_processed": 0, "forms_skipped": 1, "forms_failed": 0}, ensure_ascii=False, indent=2))
            return
        print(json.dumps(convert_form_bin(source, output, event_map), ensure_ascii=False, indent=2))
        return
    if source.is_dir() and args.recursive:
        summary = convert_tree(source, output, args.verbose, args.full, project_root)
        print(json.dumps(summary, ensure_ascii=False, indent=2))
        if summary["forms_failed"]:
            raise SystemExit(1)
        return
    parser.error("source must be a Form.bin, or a directory together with --recursive")


if __name__ == "__main__":
    main()
