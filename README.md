# Maso — AI scam checks with OpenPhish

Maso checks pasted links, messages, .eml emails and QR images using local text/URL models. OpenPhish Community is the only connected threat-data provider. No threat-service API key is required.

## Run

Backend: from C:/Projects/Maso run `start.cmd`. Frontend: from C:/Projects/MasoFront run `npm run dev`. The backend uses port 8000 unless a port argument is supplied. Restart after backend/configuration changes.

Local .env settings: MASO_API_KEY, MASO_MODEL_PATH, MASO_PHISHING_LABEL, MASO_URL_MODEL_PATH and MASO_URL_PHISHING_LABEL. Optional settings include MASO_OPENPHISH_CACHE and MASO_LOG_FILE. API keys stay on the backend; never use browser VITE variables for secrets.

Text model: ElSlay/BERT-Phishing-Email-Model, revision 708d260869707ffdb0227c3c838ce957a736c9d6. URL model: CrabInHoney/urlbert-tiny-v4-phishing-classifier, revision fd962a5cd04e20ceed46aa8a6e31a2b40d4c8916. Both use explicitly configured positive labels and local safetensors weights with remote code disabled.

## How checks work

Bare/full address-only input routes to the URL model. Other text routes to the email-text model; extracted links are also classified separately. The highest required model confidence becomes score. model_risk_level preserves the model-only classification. A matched OpenPhish URL generates an attributed finding and an unsafe result. A missing match never proves safety. Missing/stale feed data is reported as unavailable/unverified, not a completed clean lookup. Failed required inference returns no verdict; no substitute predictions are used.

OpenPhish Community downloads are cached for 12 hours. Submitted URLs are compared locally and never sent to the publisher. Exact normalized URL matching preserves path/query distinctions; matching one URL does not block its whole domain. Only feed URL hashes and metadata are stored in ignored data/openphish.json. See docs/OPENPHISH_SETUP.md for feed terms, freshness and verification. The community feed is limited and restricted to non-commercial use; appropriate permission is needed before business deployment or redistribution.

## API and frontend

POST /api/v1/analyze accepts JSON content, optional sender/reply_to, expand_links=false and external_checks=false. external_checks=true means OpenPhish lookup only. POST /api/v1/analyze/email and /api/v1/analyze/qr accept multipart file uploads with the same flags as query parameters. The frontend enables OpenPhish checking by default. Optional API redirect expansion supplies destination addresses to the URL model with per-hop SSRF/private-network protections.

Text limit: 20,000 characters. Files: 2 MiB. QR images: 4 million pixels. Entire bodies: 3 MiB. Up to 10 extracted original links. No automatic DNS-existence verdict, screenshot OCR or attachment scanning is implemented. Scores are uncalibrated model confidence, not probability of real-world harm. Classification errors remain possible.

GET /health/live and /health/ready expose process/model/feed status; /docs exposes the API contract. The feed status includes its acquisition time, entry count and SHA-256 without exposing raw feed URLs.

## Logs and verification

Structured operational logs appear in the terminal and logs/maso.log with generated request IDs, 5 MiB rotation and three backups. Submitted content, keys, sender details, filenames and URL destinations are not logged.

Backend tests: `.venv\Scripts\python -m pytest -q`. Frontend: `node --test tests/*.test.js`, `npm run lint`, `npm run build`. Real OpenPhish/model verification: `.venv\Scripts\python verify_openphish.py`. That check retrieves the publisher feed but does not open listed websites. Metadata-only results are saved in docs/openphish-verification.json.

The implementation remains a prototype. Independent model accuracy evaluation, performance/load targets and remaining PDF requirements must not be represented as completed merely because regression tests pass.
"# Maso-agent-backend" 
