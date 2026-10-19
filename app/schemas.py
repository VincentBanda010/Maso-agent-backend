from typing import Literal
from .scope import validate_safety_input
from pydantic import BaseModel, Field, field_validator


class AnalysisRequest(BaseModel):
    content: str = Field(min_length=1, max_length=20000)
    sender: str | None = Field(default=None, max_length=320)
    reply_to: str | None = Field(default=None, max_length=320)
    expand_links: bool = False
    external_checks: bool = False

    @field_validator("content")
    @classmethod
    def not_blank(cls, value):
        if not value.strip():
            raise ValueError("Enter a message or URL to check.")
        return validate_safety_input(value)


class Finding(BaseModel):
    code: str
    message: str
    weight: int = Field(ge=0, le=100)
    source: Literal["model", "observed", "threat_service"] = "model"
    severity: Literal["notice", "warning", "danger"] = "warning"


class LinkResult(BaseModel):
    url: str
    final_url: str | None = None
    redirects: list[str] = Field(default_factory=list)
    status: str = "not_requested"


class AnalysisResponse(BaseModel):
    id: str
    risk_level: Literal["Safe", "Suspicious", "Dangerous"]
    score: int = Field(ge=0, le=100)
    model_risk_level: Literal["Safe", "Suspicious", "Dangerous"]
    safety_status: Literal["unsafe", "high_risk", "suspicious", "unverified", "checks_passed"]
    color: Literal["green", "yellow", "red"]
    summary: str
    findings: list[Finding]
    checklist: list[str]
    links: list[LinkResult]
    checks: dict[str, str]
    limitations: list[str]
    threat_data: dict = Field(default_factory=dict)
    elapsed_ms: int
