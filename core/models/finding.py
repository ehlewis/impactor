
from pydantic import BaseModel, Field
from typing import Any, Dict, List

class Finding(BaseModel):
    id: str
    source: str
    severity: str
    title: str
    description: str = ''
    application_id: str = ''
    evidence: List[str] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)
