# Ordinary Form Decoder

An independent, read-only decoder of 1C ordinary forms for RLM indexing. It reads `Form.bin` and produces `Form.xml` plus `Form/Module.bsl`. It does not rebuild binary forms.

No package installation is required: use Python 3.10+ and keep `ordinary_form_rlm.py` next to `ordinary-form-events.json`. The detailed guide is [README.html](README.html) (Russian).

```powershell
python .\ordinary_form_rlm.py "C:\Work\export\Form.bin" --output "C:\Work\output"
python .\ordinary_form_rlm.py "C:\Work\export" --recursive --output "C:\Work\output"
python -m unittest discover -s tests
```

The event vocabulary is user-editable and may be incomplete. It does not assign numeric event IDs without analysis of the project's forms. A known handler is retained even when its event name cannot be resolved.

The implementation is independent of `onec-ordinary-forms`. That project informed format research and served as a comparison oracle; its source code was not used here. Thanks to its author Maxon for the published work.

Licensed under [MIT](LICENSE). Developed by synklair with contributions from OpenAI Codex; see [AUTHORS.md](AUTHORS.md).
