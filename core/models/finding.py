
from pydantic import BaseModel
from typing import List

class Finding(BaseModel):
    id: str
    source: str
    severity: str
    title: str
    description: str = ''
    application_id: str = ''
    evidence: List[str] = []
