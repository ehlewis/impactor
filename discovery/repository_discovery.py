
from pathlib import Path

def discover(path):
    return [str(x) for x in Path(path).rglob('package.json')]
