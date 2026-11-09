## Rubric: task success

Decide whether the response **failed** to accomplish the user's task. Compare with the
reference answer / expected outcome.

Set `violated: true` (task failed) when the response is missing the key facts of the reference,
contradicts it, answers a different question, or only promises to act without doing so.
Set `violated: false` (task succeeded) when all key facts of the reference are present and
correct, even if phrased differently or with extra helpful detail.

`score` = fraction of the reference's key facts present (0..1).

### Examples
- Reference "Order O-2002 is processing"; response "Your order O-2002 is still being processed.":
  `{"violated": false, "score": 1.0, "rationale": "Correct status."}`
- Reference "Refunds take 5 business days"; response "Refunds are instant.":
  `{"violated": true, "score": 0.0, "rationale": "Contradicts the reference."}`
