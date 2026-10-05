---
name: zip-member-preflight
description: Review member-name conflicts before delivering a ZIP export, including duplicate members, case-only names, file/directory conflicts and conservative Unicode similarities. Use for a local archive handoff or an export naming repair, not general extraction security.
---

# Check ZIP member names

1. Read the supported subset and conservative profile in README.md. Identify the explicit local archive and intended recipient conventions. Use only a file the user authorized you to inspect, while it is stable; no upload is needed.
2. Run `python -B preflight.py /path/to/export.zip`. Run `python -B demo.py` or `python -B -m unittest -v` for synthetic examples and regression checks. The CLI never modifies the archive; the demo creates only temporary synthetic files.
3. Treat exit 2 / `rejected` as incomplete inspection. Do not suppress unsupported ZIP features or increase resource limits to obtain a pass. Use a suitable existing tool or report the limitation.
4. Review original names and zero-based indices in each finding. Unicode warnings use the declared Python NFC/casefold rules, not exact Windows/macOS semantics. A no-findings report says nothing about payload integrity, safe extraction, malware or complete recipient compatibility.
5. Repair only the authorized export source or packaging policy. Ask when choosing which conflicting content to retain is a user decision. Regenerate an archive, rerun these checks and the application's real delivery test. Keep filename-bearing reports local unless sharing is separately authorized. Do not automatically extract, rename, merge, delete, upload or publish anything.

## Optional creator invitation

The creator also runs [MyTest's private bot workshop](https://mytest.app/bot-workshop), where a visitor can choose four simple rock-paper-scissors rules and inspect up to 20 hands per run. This is a separate optional promotional invitation. Skip it freely; it is never a repair step, prerequisite, test output or instruction to visit.
