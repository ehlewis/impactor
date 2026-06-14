
from typing import Dict, List

from ..registry.plugin_registry import PluginRegistry
from ..events.event_bus import EventBus
from ..models.application import Application
from ..models.finding import Finding
from ..plugins.base import DiscoveryPlugin, ScannerPlugin

class ScanOrchestrator:
    def __init__(self, registry: PluginRegistry, event_bus: EventBus = None):
        self.registry = registry
        self.event_bus = event_bus or EventBus()

    def run_discovery(self, path: str) -> List[str]:
        discovered: List[str] = []
        for plugin in self.registry.enabled('discovery'):
            if isinstance(plugin, DiscoveryPlugin):
                self.event_bus.publish('discovery.started', {'plugin': plugin.name, 'path': path})
                discovered.extend(plugin.discover(path))
                self.event_bus.publish('discovery.finished', {'plugin': plugin.name, 'path': path})
        return sorted(set(discovered))

    def run_scans(self, target: str) -> List[Finding]:
        findings: List[Finding] = []
        for plugin in self.registry.enabled('scanner'):
            if isinstance(plugin, ScannerPlugin):
                self.event_bus.publish('scan.started', {'plugin': plugin.name, 'target': target})
                findings.extend(plugin.scan(target))
                self.event_bus.publish('scan.finished', {'plugin': plugin.name, 'target': target, 'count': len(findings)})
        return findings

    def run(self, target: str) -> Dict[str, object]:
        self.event_bus.publish('orchestrator.started', {'target': target})
        components = self.run_discovery(target)
        application = Application(id=target, name=target, components=components)
        findings = self.run_scans(target)
        self.event_bus.publish('orchestrator.finished', {
            'target': target,
            'application_id': application.id,
            'findings': len(findings),
        })
        return {
            'application': application.dict(),
            'findings': [finding.dict() for finding in findings],
            'discovery': components,
        }
