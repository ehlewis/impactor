from pydantic import BaseModel

class EvidenceEdge(BaseModel):
    source: str
    target: str
    relationship: str
    evidence: list[str] = []
