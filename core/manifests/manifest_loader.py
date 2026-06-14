from pathlib import Path
from typing import Optional

import yaml

from core.models.manifest import ImpcatorManifest

MANIFEST_FILENAME = 'impcator.yaml'


def find_manifest(start_path: str) -> Optional[Path]:
    path = Path(start_path).resolve()
    if path.is_file():
        path = path.parent

    for current in [path] + list(path.parents):
        candidate = current / MANIFEST_FILENAME
        if candidate.is_file():
            return candidate
    return None


def load_manifest(path: str) -> ImpcatorManifest:
    manifest_path = Path(path)
    if manifest_path.is_dir():
        manifest_path = find_manifest(path)
        if manifest_path is None:
            raise FileNotFoundError(f'No {MANIFEST_FILENAME} found under {path}')
    if not manifest_path.exists():
        raise FileNotFoundError(f'Manifest path not found: {manifest_path}')

    with manifest_path.open('r', encoding='utf-8') as stream:
        raw_data = yaml.safe_load(stream) or {}

    manifest = ImpcatorManifest.parse_obj(raw_data)
    return manifest
