
from pydantic import BaseModel
from typing import List

class Application(BaseModel):
    id: str
    name: str
    description: str = ''
    components: List[str] = []
    tags: List[str] = []
