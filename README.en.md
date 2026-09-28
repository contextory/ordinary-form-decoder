# Ordinary Form Decoder

Ordinary forms live in `Form.bin`, while RLM needs their readable structure: controls, attributes, and links to handlers. This script extracts that structure into `Form.xml` and the form module into `Form/Module.bsl`. It leaves the source file untouched and cannot rebuild a binary form.

Run it on one form or recursively over an export tree, including external processors and reports. No package installation is needed: use Python 3.10+ and keep `ordinary_form_rlm.py` next to `ordinary-form-events.json`. See the [detailed guide](README.html) (Russian).

If an event type cannot be identified, the XML still retains its known handler and marks the event as unknown. Explicit `CommandBar` actions, including those in nested groups, are matched to button names by UUID; built-in platform commands are not presented as BSL handlers.

```powershell
python .\ordinary_form_rlm.py "C:\Work\export\Form.bin" --output "C:\Work\output"
python .\ordinary_form_rlm.py "C:\Work\export" --recursive --output "C:\Work\output"
python -m unittest discover -s tests
```

You can extend the event vocabulary for your own forms. It helps identify event names, but numeric IDs are inferred from the project's forms rather than the vocabulary alone.

For an external processor or report, pass `--ordinary-forms "C:\Work\DemoProject\ordinary-forms"` to reuse an existing `event-map.json`. Those explicit mappings take precedence over local ones; the shared directory is read-only, while local diagnostics remain beside the external export.
`unresolved-events.json` is created only when event IDs still need manual review. A stale empty report is removed.

The implementation is independent of `onec-ordinary-forms`. That project informed format research and served as a comparison oracle; its source code was not used here. Thanks to its author Maxon for the published work.

Licensed under [MIT](LICENSE). Developed by synklair with contributions from OpenAI Codex; see [AUTHORS.md](AUTHORS.md).
