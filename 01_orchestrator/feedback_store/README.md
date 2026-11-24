# Feedback store

`FeedbackStore` is a query facade for the existing shared `feedback_record`
contract. It delegates saving and loading to the configured contract artifact
store, so Mongo mode keeps one document in `feedback_records`; it does not
write a second feedback copy.

```python
feedback_store = workflow.outputs.feedback_store
feedback = feedback_store.get_by_task(task_id)
bundle = feedback_store.get_bundle(task_id)
```

`get_bundle()` resolves the record's artifact references and returns the
original Red proposal, telemetry evidence, reviewed labels, Blue proposal,
candidate rule, both match sets, and Judge result under `artifact_payloads`.
This leaves the role-specific material available for later feedback-memory
work without duplicating it in the feedback contract.

`retrieval_eligible` is a read-time conservative hint: it is true only when
the Judge decision is `PASS`. Rejected and inconclusive results are not
presented as positive examples. The shared feedback contract remains unchanged
and continues to store its canonical decision and artifact references.

Saving the same feedback again for a task returns the existing reference when
all record contents except `recorded_at` match. Conflicting feedback for the
same task is rejected. This check is read-then-write; the shared Mongo mapping
does not currently enforce a unique task ID for feedback, so simultaneous
completion attempts are not protected from creating duplicate documents by a
database uniqueness constraint.

The current dev suite checks lookup and artifact resolution in memory and
Mongo-backed storage. Feedback retrieval does not automatically select prior
rounds for Red or Blue; that feedback-memory policy is a later workflow
feature.
