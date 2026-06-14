import os
from pathlib import Path
from typing import Optional

from dotenv import load_dotenv

ENV_PATH = Path('.') / '.env'
LOCAL_ENV_PATH = Path('.') / '.env.local'


def load_environment(path: Optional[str] = None) -> None:
    env_path = Path(path) if path else ENV_PATH
    if env_path.exists():
        load_dotenv(dotenv_path=env_path)

    if LOCAL_ENV_PATH.exists():
        load_dotenv(dotenv_path=LOCAL_ENV_PATH, override=True)


def get_env_variable(key: str, default: Optional[str] = None) -> Optional[str]:
    value = os.getenv(key, default)
    if value is None:
        print(f'Warning: {key} is not configured in .env or the environment.')
    return value
