from pydantic import BaseModel
from typing import Dict, List

class AttackSurfaceNode(BaseModel):
    id: str
    type: str
    name: str
    properties: Dict[str, str] = {}

class AttackSurfaceGraph(BaseModel):
    nodes: List[AttackSurfaceNode] = []
    edges: List[Dict[str, str]] = []
