
from abc import ABC, abstractmethod
from typing import Sequence

class Plugin(ABC):
    name: str = ''
    version: str = '0.1.0'
    enabled: bool = True
    category: str = 'generic'

    @property
    def metadata(self):
        return {
            'name': self.name,
            'version': self.version,
            'category': self.category,
            'enabled': self.enabled,
        }

class DiscoveryPlugin(Plugin):
    category = 'discovery'

    @abstractmethod
    def discover(self, path: str) -> Sequence[str]:
        raise NotImplementedError

class ScannerPlugin(Plugin):
    category = 'scanner'

    @abstractmethod
    def scan(self, target: str) -> Sequence['Finding']:
        raise NotImplementedError

class AssetProviderPlugin(Plugin):
    category = 'asset'

    @abstractmethod
    def discover_assets(self, path: str) -> Sequence[dict]:
        raise NotImplementedError
