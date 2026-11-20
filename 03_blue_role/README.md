# `03_blue_role/`: the Blue role

Blue receives a detection rule, reviewed false positives, and the attacks that must stay detected.
It proposes one small, structured edit set (`blue_proposal`). It never runs searches, never
judges, and cannot change the judge's criteria.

## Status

| Part | Status | Notes |
|---|---|---|
| `interfaces/inputs/` | done (draft) | `blue_input` contract + examples. |
| `../00_shared_contracts/blue_proposal/` | done (draft) | `blue_proposal` contract + examples. |
| `schemas/` | done | Models, validation against the JSON Schemas, serializer, error envelope. |
| `rule_edits/` | in progress | `apply_edits` turns structured edits into a candidate Sigma rule and a diff. |
| Pre-flight checks | todo | Policy checks on a proposal before the judge runs. |
| Retrieval of reference rules | todo | |
| `prompts/`, `role_context/` | todo | Blue prompt, context builder, model call. |

## Rule edits

The model only proposes edits as data. `rule_edits/apply.py` is the one place that applies them,
so the result is reproducible:

- `add_exclusion` adds a `filter_autosoc_<n>` block and rewrites the condition to
  `(<old condition>) and not filter_autosoc_<n>`.
- `narrow_selection` adds field conditions to an existing selection. It refuses to touch filter
  blocks (that would widen the rule) and refuses to overwrite a key that already exists.

## Running the tests

```
cd 03_blue_role
python -m pip install -r requirements.txt
python -m pytest
```

Run from `03_blue_role/` (like `02_red_role/`), so the local `schemas` package is the Blue one.
