from pydantic import BaseModel
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
