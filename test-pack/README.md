# Maso real-world test pack

## Run in Postman
1. Start Maso from VS Code with `start.cmd`. Model setup must be complete; run Model readiness first.
2. Import Maso-Real-World.postman_collection.json and Maso-Local.postman_environment.json.
3. Select Maso Local, set api_key locally from .env, and use http://127.0.0.1:8000 as base_url (change for your chosen port).
4. Set request timeout to 45000 ms and run sequentially. The model accepts one active inference per process.
5. Run folders 1–4. Scripts > Post-response contains assertions; Test Results shows pass/fail.
6. Upload paths point to C:/Projects/Maso/test-pack. If needed, select each file under Body > form-data > file. Postman may request permission to read this folder.
7. Folder 5 is diagnostic for raw MIME/HTML captures. A 422/503 is no verdict, not a correct phishing detection.

## Contents and provenance
- 9 real-world redacted source samples selected from cw-l/email-corpus: six scam-lure cases plus three exploratory spam/ambiguous cases.
- 13 normalized .eml files and matching text files: nine source derivatives plus four synthetic benign controls.
- 5 generated QR fixtures: two encode captured scam email text, two benign text, one benign URL. These are newly generated test images, NOT original criminal QR artifacts.
- 2 invalid image controls.
- Original published source files, license, source README, source URLs, revision and SHA-256 hashes in manifest.json. Additional downloaded source samples remain available under source-emails.

Source: https://github.com/cw-l/email-corpus
Revision: 75b488148d5560109d6fb0c6646d417d7271f66a
The publisher describes the corpus as real-world spam/scam/phishing with contributor identifiers redacted and URLs defanged. We preserve that defanging and never contact the destinations. Source files are not rendered or executed. Upload .eml files through Postman rather than opening them in an email client.

Normalized files are explicit derivatives: readable body text replaces HTML MIME; styles and attachments are omitted; sender/recipient are synthetic. Full source files remain separate. Normalized emails are not truncated. QR payloads use at most the first 350 characters and are explicitly marked as excerpts in manifest.json. These derivatives test semantic model inference, not sender authentication or original MIME fidelity.

## Reading results
Functional assertions require HTTP 200, checks.ai=completed, no rules check, valid score/color/verdict and network checks not requested. Quality probes expect scam-lure cases to be Suspicious/Dangerous and synthetic benign controls to be Safe. Those expectations are manual test labels, not independently verified ground truth. Advertising/grant examples are exploratory, without class assertions.

Expect possible failures: false negatives and false positives are exactly what this pack is designed to reveal. Do not change expected labels merely to make tests pass. This small curated set is not a statistically representative benchmark; possible training overlap is unknown. Bare URL/QR classification is not validated by the email model. A model failure or oversized input can yield 503; this is never a phishing verdict. Read manifest.json for all provenance and transformations.

No live model evaluation has been run as part of creating this pack. Fixtures are checked for MIME parsing, QR decoding and collection integrity.
