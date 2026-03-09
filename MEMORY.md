## Project Memory

- UI templates must remain as separate HTML/JS files under `src/ui/templates/`. Do not generate or bundle them into a single `templates.js`.
- `master.yaml` is the single source of truth for configuration shape. Any feature that adds/changes config keys must update `master.yaml` in the same change.
