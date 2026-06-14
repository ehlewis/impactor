from pydantic import BaseModel
from typing import Dict, List

class Asset(BaseModel):
    id: str
    name: str
    type: str
    labels: List[str] = []
    tags: List[str] = []
    metadata: Dict[str, str] = {}
    exposure: Dict[str, float] = {}
