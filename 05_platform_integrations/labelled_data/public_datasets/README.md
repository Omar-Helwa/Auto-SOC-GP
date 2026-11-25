# Datasets for AutoSOC testing

```
datasets/
  original/                              untouched downloads (git-ignored)
    attacks/splunk_attack_data/<technique>__<scenario>/   attack logs + manifest.yml
    attacks/benign/<name>/                                your benign logs (add these)
    rules/splunk_security_content/{detections,macros}/    Splunk detection rules
  prepared/<eval_set_id>/                outputs in the shared-contract formats (git-ignored)
    events/events.jsonl                  normalized events with event_id
    events/splunk_hec.jsonl              ready for Splunk HTTP Event Collector
    labels/reviewed_label_set.json       telemetry_evidence/reviewed_label_set
    detections/<detection_id>.json       round_request.detection
    detections/index.json                rule name, ATT&CK, source file, original SPL
    manifest.json                        inputs, hashes, counts
  scripts/
```

## Run

```
cd 05_platform_integrations/labelled_data/public_datasets/scripts
pip install pyyaml jsonschema
python download_attack_data.py                       # attacks -> original/attacks
python download_rules.py                             # rules   -> original/rules
python prepare_rules.py --eval-set-id evalset-ps-v1  # rules   -> prepared/.../detections
python build_evaluation_set.py --eval-set-id evalset-ps-v1   # events + labels
python validate_prepared.py --eval-set-id evalset-ps-v1      # check against schemas
python upload_to_splunk.py ../prepared/evalset-ps-v1/events/splunk_hec.jsonl
```

For a compact Splunk demo with the imported LSASS remote-thread rule:

```
python build_demo_subset.py
python validate_prepared.py --eval-set-id evalset-demo-lsass-v1
python upload_to_splunk.py ../prepared/evalset-demo-lsass-v1/events/splunk_hec.jsonl
```

The subset contains attack events matching the rule's initial search and all
available benign events. Labels retain their original review status; the subset
must not be treated as judge-ready until an authorized reviewer reviews it.

`evalset-demo-lsass-v1` has no benign event the LSASS rule matches. Version 2
adds three SYNTHETIC benign false positives. They are constructed Sysmon
EventID 8 events from a fictional "Contoso EDR" agent, modelled on the rule's
documented false positive (legitimate security tools), and are not recorded
data. They live in `original/attacks/benign/lab__synthetic_lsass_edr/`, so they
are labelled `source: lab_telemetry`. The assembled runner therefore refuses
hosted models for this set.
```
python make_synthetic_lsass_benign.py
python build_evaluation_set.py --eval-set-id evalset-multi-v2 --dataset-version 2026-11-25
python prepare_rules.py --eval-set-id evalset-multi-v2
python build_demo_subset.py --source-eval-set evalset-multi-v2 --eval-set-id evalset-demo-lsass-v2
python validate_prepared.py --eval-set-id evalset-demo-lsass-v2
```

Record a human review of one prepared set with `review_labels.py`. It prints
each label group with an example event and asks the reviewer to type a
confirmation phrase. `--sheet review.csv` exports every event for a detailed
check without changing anything. `--dispute EVENT_ID` keeps the set incomplete,
and `--relabel EVENT_ID=benign` corrects a label. The previous label file is
kept as a `.bak-<timestamp>` copy.
```
python review_labels.py --eval-set-id evalset-demo-lsass-v2 --reviewer "<name>" --sheet review.csv
python review_labels.py --eval-set-id evalset-demo-lsass-v2 --reviewer "<name>"
```

The uploader requires HTTPS by default. Plain HTTP is refused unless
`SPLUNK_HEC_ALLOW_INSECURE_HTTP=1` is explicitly set for an approved isolated
lab upload. That setting permits the HEC token to travel unencrypted.

`prepare_rules.py` keeps only detections whose test data you downloaded. To find more:
`python prepare_rules.py --eval-set-id x --technique T1003.001`, then download those scenarios.

Labels are per file and start "unreviewed". Spot-check, then rerun
`build_evaluation_set.py` with `--reviewer "<name>"`.

Sources: Splunk Attack Data (github.com/splunk/attack_data) and Splunk Security Content
(github.com/splunk/security_content; the rule corpus used by RuleGenie and the
"Evolution of Log-Based Detection Rules" paper).

## Evaluation sets built so far

| eval_set_id | attack events | benign events | sources |
|---|---|---|---|
| evalset-ps-v1 | 30,301 | 0 | Splunk Attack Data T1059.001 (3 scenarios) |
| evalset-multi-v1 | 45,222 | 116 | Splunk Attack Data T1059.001, T1053.005, T1003.001 (5 scenarios); SOCBED benign (AMIDES, USENIX Security 2024) |

Benign events come from SOCBED (github.com/fkie-cad/amides, data/socbed). Its
process_creation set has 701 lines but only 102 unique command lines; duplicates are
removed by the builder. Add your own lab benign logs under original/attacks/benign/lab__<name>/
for a larger benign side.

Rebuild evalset-multi-v1:
    python download_benign_socbed.py
    python download_attack_data.py T1003.001/atomic_red_team T1053.005/atomic_red_team T1053.005/schtasks T1053.005/winevent_scheduled_task_created_to_spawn_shell
    python download_rules.py
    python prepare_rules.py --eval-set-id evalset-multi-v1
    python build_evaluation_set.py --eval-set-id evalset-multi-v1 --dataset-version 2026-10-27
    python validate_prepared.py --eval-set-id evalset-multi-v1
