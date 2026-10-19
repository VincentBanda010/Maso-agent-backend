# Maso Postman package

1. Start the backend from VS Code: `cd C:\Projects\Maso`, then `start.cmd`.
2. Extract the ZIP. In Postman choose Import and select both JSON files.
3. Select **Maso Local** as the active environment.
4. Set the environment's `api_key` locally to the value of `MASO_API_KEY` in Maso's `.env`. This package contains no API key.
5. Set Postman's request timeout to 45000 ms. Use sequential requests, not parallel runs.
6. Send **Model readiness — run first**. Its test requires `ai: ready`.
7. Run the Model analysis folder. Inspect the verdict, score, check statuses and limitations. Tests validate completed model inference without rules; they do not assume the model predicts each example correctly.
8. For uploads, choose the supplied `.eml` or PNG in Body > form-data > file. Run the upload requests separately after choosing the files.

Default backend: http://127.0.0.1:8000. If using port 8001, change `base_url`; use `start.cmd --port 8001` so `.env` is loaded. The frontend is not needed.

Connection refused means the backend is not running at `base_url`. 401 means the local API key is missing or wrong. 503 means the model is unavailable, busy or unable to process the input; it is not a verdict. A readiness result of `not_configured` means no model was loaded. Startup errors about Transformers or model files require finishing installation/download first.

Only model inference determines the verdict. Network expansion and external checks are off. Test URLs use example domains and are not visited. Email classification is the model's intended task; bare URLs and QR payloads are exploratory. Scores are uncalibrated model phishing confidence. This collection does not establish real-world accuracy.
