
from typing import Dict, List, Optional

class PluginRegistry:
    def __init__(self):
        self.plugins: Dict[str, object] = {}

    def register(self, plugin: object) -> None:
        if not getattr(plugin, 'name', None):
            raise ValueError('Plugin must have a name')
        if plugin.name in self.plugins:
            raise ValueError(f"Plugin '{plugin.name}' is already registered")
        self.plugins[plugin.name] = plugin

    def get(self, name: str) -> Optional[object]:
        return self.plugins.get(name)

    def all(self, category: Optional[str] = None) -> List[object]:
        if category is None:
            return list(self.plugins.values())
        return [p for p in self.plugins.values() if getattr(p, 'category', None) == category]

    def enabled(self, category: Optional[str] = None) -> List[object]:
        return [p for p in self.all(category) if getattr(p, 'enabled', True)]
