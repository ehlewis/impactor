from pydantic import BaseModel
from typing import List

class AttackPath(BaseModel):
    id: str
    path: List[str]
    score: float
    priority: str
    evidence: List[str] = []
