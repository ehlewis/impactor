from pydantic import BaseModel, Field
from typing import List

class FixRecommendation(BaseModel):
    id: str
    title: str
    description: str
    impacted_findings: List[str]
    effort: str
    expected_risk_reduction: float
    priority: str
    remediation: str
    shared_code: List[str] = Field(default_factory=list)
