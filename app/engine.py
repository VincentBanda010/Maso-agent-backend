import asyncio
import html
import math
import re
import time
import uuid
import aiohttp

from .observability import log_event
from .network import expand, UnsafeURL
from .providers import url_inputs
from .schemas import AnalysisRequest, AnalysisResponse, Finding, LinkResult

URL_RE = re.compile(r"(?:https?://|www\.)[^\s<>\"']+", re.I)
def extract_urls(text):
    addresses = url_inputs(html.unescape(text))
    if addresses is not None:
        return list(dict.fromkeys(addresses))
    return list(dict.fromkeys(("https://" + u if u.lower().startswith("www.") else u)
                             for u in (m.rstrip(".,;!?) ]}") for m in URL_RE.findall(html.unescape(text)))))


async def analyze(request: AnalysisRequest, providers) -> AnalysisResponse:
    start = time.monotonic()
    urls = extract_urls(request.content)
    limitations = ["A low score does not prove safety. New or targeted scams may evade these checks."]
    input_kind = "url" if url_inputs(request.content) is not None else "text"
    checks = {"ai": providers.url_model_status if input_kind == "url" else providers.model_status,
              "model_type": input_kind,
              "threat_intelligence": "not_requested", "link_expansion": "not_requested"}
    if len(urls) > 10:
        limitations.append("Only the first 10 extracted links are included in additional model analysis.")
    links = [LinkResult(url=url) for url in urls[:10]]
    log_event("analysis.started", model_type=input_kind, characters=len(request.content),
        link_count=len(urls), expand_links=request.expand_links, external_checks=request.external_checks)
    threat_provider = providers.threat_provider
    checks["threat_provider"] = threat_provider
    provider_name = "OpenPhish Community"
    findings = []
    probability = None

    async def expand_one(link):
        try:
            async with asyncio.timeout(2.5):
                link.final_url, link.redirects = await expand(link.url)
            link.status = "completed"
            log_event("link.expansion_completed", redirect_count=len(link.redirects))
        except (TimeoutError, OSError, UnsafeURL, aiohttp.ClientError):
            link.status = "blocked_or_unavailable"
            log_event("link.expansion_unavailable")

    if request.expand_links and links:
        await asyncio.gather(*(expand_one(link) for link in links))
        checks["link_expansion"] = "completed" if all(l.status == "completed" for l in links) else "partial"
        if checks["link_expansion"] == "partial":
            limitations.append("Some destinations could not be expanded safely; their final destinations are unknown.")
    elif links:
        limitations.append("Link destinations were not contacted. Enable expand_links to follow HTTP redirects.")

    async def ai():
        nonlocal probability
        log_event("model.started", model_type=input_kind)
        try:
            async with asyncio.timeout(max(0.05, 30 - (time.monotonic() - start))):
                predictions = [await providers.classify(request.content)]
                if links and (input_kind == "text" or any(link.redirects for link in links)):
                    checks["linked_urls_ai"] = "started"
                    for link in links:
                        candidates = list(dict.fromkeys([link.url, *link.redirects]))
                        predictions.append(await providers.classify("\n".join(candidates)))
                    checks["linked_urls_ai"] = "completed"
                if any(value is None or not isinstance(value, (int, float)) or isinstance(value, bool)
                       or not math.isfinite(value) or not 0 <= value <= 1 for value in predictions):
                    raise ValueError("Invalid or missing model confidence")
                probability = max(predictions)
            checks["ai"] = "completed"
            log_event("model.completed", model_type=input_kind, phishing_confidence=round(probability, 6))
            if probability >= 0.5:
                findings.append(Finding(code="ai_phishing", message="The model detected phishing-like patterns in the submitted content or its links.", weight=round(probability * 100)))
        except Exception as exc:
            log_event("model.failed", model_type=input_kind, error_type=type(exc).__name__)
            checks["ai"] = "unavailable"

    async def threat_lookup():
        if not request.external_checks or not links:
            return
        log_event("threat_intelligence.started", link_count=len(links))
        try:
            async with asyncio.timeout(3):
                result = await providers.reputation(list(dict.fromkeys(
                    address for link in links for address in [link.url, *link.redirects])))
            if result is not None and not isinstance(result,bool):
                raise ValueError("Invalid threat-service response")
            checks["threat_intelligence"]="not_configured" if result is None else "completed"
            if result is True:
                findings.append(Finding(code="known_threat",message=f"{provider_name} lists a harmful URL.",
                    weight=0,source="threat_service",severity="danger"))
            log_event("threat_intelligence.completed",status=checks["threat_intelligence"],flagged=any(f.code=="known_threat" for f in findings))
        except Exception as exc:
            checks["threat_intelligence"] = "unavailable"
            log_event("threat_intelligence.failed", error_type=type(exc).__name__)

    await asyncio.gather(ai(), threat_lookup())
    if checks["ai"] != "completed" or probability is None:
        log_event("analysis.no_verdict", model_type=input_kind, model_status=checks["ai"])
        from fastapi import HTTPException
        raise HTTPException(503, "The phishing model is unavailable. No analysis verdict was produced.")
    if request.external_checks and links and threat_provider == "openphish":
        limitations.append("OpenPhish Community is a limited feed updated every 12 hours. A URL not listed is not proof of safety.")
    if input_kind == "url":
        limitations.append("The URL model evaluates address text only; it does not verify page content or website safety.")
        limitations.append("For multiple URLs, the score is the highest individual model phishing confidence.")
    else:
        limitations.append("The message and its extracted links were checked separately when links were present. English email text is the text model’s intended input.")
    limitations.append("The score is the highest model phishing confidence across the content and checked addresses, not a calibrated probability of real-world harm.")
    score = round(probability * 100)
    level = "Dangerous" if probability >= .85 else "Suspicious" if probability >= .5 else "Safe"
    model_risk_level = level
    known_threat = any(item.code == "known_threat" for item in findings)
    incomplete_lookup = bool(links) and request.external_checks and checks["threat_intelligence"] != "completed"
    if known_threat:
        level = "Dangerous"
    safety_status = ("unsafe" if known_threat else "high_risk" if level == "Dangerous"
        else "suspicious" if level == "Suspicious" else "unverified" if incomplete_lookup else "checks_passed")
    if incomplete_lookup:
        limitations.append("The requested threat-feed lookup did not complete. Website reputation is unverified.")
    summary = {"Dangerous": "The model classified this content as likely phishing. Do not send money, enter credentials, or follow the links.",
               "Suspicious": "Treat this content cautiously: the model detected possible phishing. Verify it through a trusted contact method.",
               "Safe": "The model classified this content as likely benign. This is not a guarantee that the content is safe."}[level]
    if known_threat:
        summary = "Unsafe link: " + next(f.message for f in findings if f.code == "known_threat") + " Do not open it or enter personal details."
    log_event("analysis.completed", model_type=input_kind, risk_level=level, score=score, safety_status=safety_status,
        elapsed_ms=round((time.monotonic() - start) * 1000, 2))
    return AnalysisResponse(id=str(uuid.uuid4()), risk_level=level, model_risk_level=model_risk_level, score=score,
        safety_status=safety_status, color="yellow" if safety_status == "unverified" else {"Safe": "green", "Suspicious": "yellow", "Dangerous": "red"}[level], summary=summary,
        findings=findings, checklist=[
            "Open the organization's official app or type its known website address yourself.",
            "Verify payment or account requests using a phone number you already trust.",
            "Never share passwords, one-time codes, or recovery phrases."], links=links,
        threat_data=providers.threat_metadata() if request.external_checks and links else {},
        checks=checks, limitations=limitations, elapsed_ms=round((time.monotonic()-start)*1000))
