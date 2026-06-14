from pydantic import BaseModel
from typing import Dict, List, Optional

class ApplicationManifest(BaseModel):
    name: str
    id: str
    path: Optional[str] = None
    description: Optional[str] = None
    business_context: Dict[str, str] = {}
    deployments: List[Dict[str, str]] = []
    critical_data: List[str] = []

class ImpcatorManifest(BaseModel):
    version: str = '1.0'
    applications: List[ApplicationManifest] = []
    repository: Optional[Dict[str, str]] = None
    deployments: List[Dict[str, str]] = []
    metadata: Dict[str, str] = {}
