# OpenPhish connection

Maso uses OpenPhish Community as its only threat-data provider. No API key is required. The frontend enables Check OpenPhish scam reports by default; users can turn it off for AI-only analysis.

Start the backend with start.cmd and the frontend with npm run dev. /health/ready reports threat_intelligence.provider, status, entry count, fetched_at, upstream_modified and a feed SHA-256. An expired or missing feed reports unavailable, not ready. Status configured is not used to claim successful feed retrieval.

The official feed is retrieved from https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt. It is cached locally for 12 hours, matching the publisher's community update frequency. Submitted URLs are compared locally; they are not transmitted to OpenPhish. The ignored data/openphish.json file stores URL hashes and feed metadata, not raw user input. No phishing pages are opened during this check. Refreshing retrieves only the publisher's feed file.

Matching uses the full normalized URL, not the entire domain: scheme/hostname/default ports and empty paths are normalized; fragments are ignored; path and query distinctions remain. A match generates an explicitly attributed threat_service finding and an unsafe result. A no-match means only that the address is not listed in the limited community feed. Model score and model_risk_level remain separate. A model failure still produces no combined analysis verdict; feed evidence is not substituted for inference.

Missing, malformed, oversized or stale data is not accepted as a completed lookup. When a stale feed cannot be refreshed, the requested check returns unavailable/unverified; it does not quietly reuse stale data as a clean result. Startup attempts a refresh, and selected lookups refresh expired data on demand. No recurring automation was created.

Verification: `.venv\Scripts\python verify_openphish.py` retrieves the real feed, checks a listed URL and an unlisted control, then runs the listed URL through the installed model and combined analysis. It never opens a listed website and writes a metadata-only report under docs/openphish-verification.json. Tests run with `.venv\Scripts\python -m pytest -q`; frontend checks use `node --test tests/*.test.js`.

Use restrictions: the Community feed is limited, updates every 12 hours and is non-commercial. The publisher permits academic/independent/personal research subject to its terms. Product/business use or redistribution may require OpenPhish's written permission. This connection is for the stated non-commercial competition research prototype; obtain appropriate permission before business deployment or redistribution. The app does not publish raw feed contents.

Sources:
- https://openphish.com/phishing_feeds.html
- https://github.com/openphish/public_feed
- https://openphish.com/terms.html
