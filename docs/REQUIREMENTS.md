# Current scope — model-only inference

The user requires model-driven scam detection, not added heuristic or external verdict rules.

Implemented: local text and URL models; correct routing of bare/full URLs; classification of embedded links; QR decoding; email parsing; uploads; short risk guidance; request/model logs. Scores and verdicts depend only on model outputs. Display templates explain the category without inventing model explanations.

Removed: automatic DNS availability checks, DNS-based statuses, external threat reputation execution, external verdict overrides, the deeper-check frontend control, and incomplete-external-check overrides of low model risk.

Retained infrastructure: input validation, a limited non-scoring scope filter, authentication, body/file limits, model token/concurrency limits, QR decoding and email parsing. Optional direct API HTTP redirect collection feeds destination addresses into the URL model; network protections do not determine the risk score.

Known gaps: false positives and possible false negatives; unvalidated local-language/SMS performance; no reliable causal explanation for specific domain tricks; no screenshot OCR, email sender authentication or attachment malware scan. The small model diagnostic is not a validated benchmark. OpenPhish Community is the only connected threat feed; there is no APWG/FBI feed.

Competition claims should describe AI-based scam-risk prediction, not guaranteed website verification, detection of every spoofed domain, or live APWG/FBI data access. Model improvement requires independent labeled data and evaluation; inference errors must not be hidden by hardcoded exceptions.
