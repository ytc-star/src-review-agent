from typing import Literal

from pydantic import BaseModel, Field


class AnalysisResult(BaseModel):
    vulnerability_type: str = "待分类"
    affected_asset: str = ""
    key_parameters: list[str] = Field(default_factory=list)
    auth_required: bool | None = None
    evidence_quality: Literal["low", "medium", "high"] = "low"
    missing_evidence: list[str] = Field(default_factory=list)
    impact: str = "需人工确认实际影响"
    severity_suggestion: Literal["Info", "Low", "Medium", "High", "Critical"] = "Low"
    review_suggestion: Literal["建议成立", "需要进一步验证", "证据不足"] = "需要进一步验证"
    verification_steps: list[str] = Field(default_factory=list)
    remediation: list[str] = Field(default_factory=list)
    reasoning: list[str] = Field(default_factory=list)

