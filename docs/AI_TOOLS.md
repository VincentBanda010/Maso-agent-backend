# Active analysis components

- Local text classifier: ElSlay/BERT-Phishing-Email-Model, pinned to 708d260869707ffdb0227c3c838ce957a736c9d6; positive label LABEL_1.
- Local URL classifier: CrabInHoney/urlbert-tiny-v4-phishing-classifier, pinned to fd962a5cd04e20ceed46aa8a6e31a2b40d4c8916; positive label LABEL_1.
- Threat data: OpenPhish Community only. Cached exact-URL lookup; no API key or transmission of submitted URLs to the publisher.
- QR decoding: local OpenCV/Pillow. QR content reaches the shared analysis engine.

The model score, model-only risk level and attributed threat-feed findings remain separate. A feed match warns about a listed URL. No match does not establish safety. Required model failure returns no verdict; an expired feed that cannot refresh is not treated as clean.

See OPENPHISH_SETUP.md for feed freshness, use restrictions and the live verification command. The current small diagnostic evaluation is not a held-out accuracy benchmark. Independent labeled data, campaign/time-separated evaluation, false-positive/false-negative measurements and realistic latency/load tests remain necessary before production claims.
