# Ordinary Form Decoder

Независимый read-only разборщик обычных форм 1С для индексации через RLM. Он читает `Form.bin` и создаёт `Form.xml` и `Form/Module.bsl`. Обратной сборки нет.

Разборщик не требует установки пакета: нужен Python 3.10+ и файлы `ordinary_form_rlm.py` и `ordinary-form-events.json` в одном каталоге. Подробная справка находится в [README.html](README.html).

```powershell
python .\ordinary_form_rlm.py "C:\Work\export\Form.bin" --output "C:\Work\output"
python .\ordinary_form_rlm.py "C:\Work\export" --recursive --output "C:\Work\output"
python -m unittest discover -s tests
```

Словарь событий — редактируемая пользователем подсказка для анализа обработчиков; он не гарантирует полноту и не назначает числовые ID без анализа форм проекта. Неизвестное имя события не приводит к потере найденного обработчика.

Реализация разработана отдельно от `onec-ordinary-forms`. Этот проект помогал изучать формат и сравнивать результаты, но его исходный код здесь не использован. Благодарим автора Maxon за опубликованную работу.

Лицензия — [MIT](LICENSE). Разработка: synklair при участии OpenAI Codex; подробности в [AUTHORS.md](AUTHORS.md).
