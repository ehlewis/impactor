from pydantic import BaseModel
from typing import List

class ApplicationAssetMapping(BaseModel):
    application_id: str
    asset_id: str
    confidence: float
    evidence: List[str] = []
