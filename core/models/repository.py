from pydantic import BaseModel
from typing import List

class Repository(BaseModel):
    id: str
    name: str
    path: str
    applications: List[str] = []
    type: str = 'single-application'
