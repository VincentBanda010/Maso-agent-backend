import asyncio
import os
import re

from .observability import log_event
from .openphish import OpenPhishFeed


def url_inputs(text):
    """Recognize address-only input; normalization never assesses scam risk."""
    from urllib.parse import urlsplit
    parts = text.strip().split()
    addresses = []
    for value in parts:
        value = value.rstrip(".,;!?) ]}")
        if re.fullmatch(r"https?://[^\s<>]+", value, re.I):
            addresses.append(value)
            continue
        # Bare email addresses and ordinary words are not website addresses.
        if "@" in value or not value or any(char in value for char in '<>"\\'):
            return None
        try:
            parsed = urlsplit("https://" + value)
            host = parsed.hostname
            if not host:
                return None
            host = host.encode("idna").decode("ascii")
            if not re.fullmatch(r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:[a-z]{2,63}|xn--[a-z0-9-]+)", host, re.I):
                return None
            parsed.port  # Invalid ports are not accepted as bare addresses.
        except (ValueError, UnicodeError):
            return None
        addresses.append("https://" + value)
    return addresses if addresses else None


class Providers:
    def __init__(self):
        self.classifier = None
        self.model_status = "not_configured"
        self.url_classifier = None
        self.url_model_status = "not_configured"
        self.gate = asyncio.Semaphore(1)
        self.openphish = OpenPhishFeed()

    def load(self):
        # Both snapshots load locally with safetensors and remote code disabled.
        def load_classifier(path, positive, fast):
            log_event("model.loading", model_type="url" if fast else "text")
            from transformers import AutoTokenizer, AutoModelForSequenceClassification, pipeline
            tokenizer = AutoTokenizer.from_pretrained(path, use_fast=fast,
                local_files_only=True, trust_remote_code=False)
            model = AutoModelForSequenceClassification.from_pretrained(path,
                local_files_only=True, trust_remote_code=False, use_safetensors=True)
            if positive.casefold() not in {label.casefold() for label in model.config.id2label.values()}:
                raise ValueError("Configured phishing label not found in model configuration")
            return pipeline("text-classification", model=model, tokenizer=tokenizer, device=-1)

        path = os.environ.get("MASO_MODEL_PATH")
        label = os.environ.get("MASO_PHISHING_LABEL")
        if not path or not label:
            raise RuntimeError("MASO_MODEL_PATH and MASO_PHISHING_LABEL must be configured")
        if path:
            self.classifier = load_classifier(path, label, False)
            self.model_status = "ready"
            log_event("model.loaded", model_type="text")
        path = os.environ.get("MASO_URL_MODEL_PATH")
        label = os.environ.get("MASO_URL_PHISHING_LABEL")
        if not path or not label:
            raise RuntimeError("MASO_URL_MODEL_PATH and MASO_URL_PHISHING_LABEL must be configured")
        if path:
            self.url_classifier = load_classifier(path, label, True)
            self.url_model_status = "ready"
            log_event("model.loaded", model_type="url")

    async def classify(self, text):
        urls = url_inputs(text)
        classifier = self.url_classifier if urls is not None else self.classifier
        if not classifier:
            log_event("model.not_configured", model_type="url" if urls is not None else "text")
            raise RuntimeError("Required model is not loaded")
        if urls is not None and len(urls) > 10:
            raise ValueError("Submit at most 10 URLs per request")
        label_setting = "MASO_URL_PHISHING_LABEL" if urls is not None else "MASO_PHISHING_LABEL"
        positive = os.environ.get(label_setting)
        if not positive:
            raise RuntimeError("Required model label is not configured")
        if self.gate.locked():
            log_event("model.busy")
            raise RuntimeError("Classifier is busy")
        await self.gate.acquire()
        async def run():
            try:
                # Keep the gate until native inference finishes, even if a request times out.
                # Reject oversize model input rather than silently ignoring its tail.
                def infer():
                    probabilities = []
                    for value in urls if urls is not None else [text]:
                        tokens = classifier.tokenizer(value, truncation=False)["input_ids"]
                        limit = classifier.model.config.max_position_embeddings
                        log_event("model.tokenized", tokens=len(tokens), token_limit=limit, model_type="url" if urls is not None else "text")
                        if len(tokens) > limit:
                            raise ValueError("Input exceeds classifier token limit")
                        output = classifier(value, truncation=False, top_k=None)
                        matches = [float(item["score"]) for item in output
                                   if item["label"].casefold() == positive.casefold()]
                        if len(matches) != 1:
                            raise ValueError("Model output must contain exactly one configured phishing label")
                        probabilities.append(matches[0])
                    return max(probabilities)
                return await asyncio.to_thread(infer)
            finally:
                self.gate.release()
        task = asyncio.create_task(run())
        task.add_done_callback(lambda t: t.exception() if not t.cancelled() else None)
        return await asyncio.shield(task)


    @property
    def threat_provider(self):
        return "openphish"

    def threat_metadata(self):
        return self.openphish.metadata()

    async def prepare_threat_service(self):
        try:
            await self.openphish.refresh()
            log_event("threat_feed.ready", entries=len(self.openphish.hashes))
        except Exception as exc:
            log_event("threat_feed.unavailable",error_type=type(exc).__name__)

    async def reputation(self, urls):
        return await self.openphish.lookup(urls)
