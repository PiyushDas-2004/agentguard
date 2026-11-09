## Rubric: faithfulness (groundedness)

Decide whether the answer contains claims **not supported by the provided context**.

Split the answer into factual claims. A claim is supported if the context states it or it
follows directly from the context. Generic politeness ("Happy to help") is not a claim.

Set `violated: true` if fewer than 70% of the claims are supported, or if any claim contradicts
the context. Otherwise `violated: false`.

`score` = fraction of supported claims (0..1).

### Examples
- Context "Standard shipping takes 3-5 business days."; answer "Shipping takes 3-5 business
  days.": `{"violated": false, "score": 1.0, "rationale": "Fully supported."}`
- Same context; answer "Shipping is free and takes one day.":
  `{"violated": true, "score": 0.0, "rationale": "Both claims unsupported."}`
