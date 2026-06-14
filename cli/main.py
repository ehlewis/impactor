
import sys
import os
from pathlib import Path
import json
from typing import Optional

import typer

# Ensure repo root is on sys.path so `import core` works when running CLI directly
_REPO_ROOT = Path(__file__).resolve().parents[1]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from core.ai.code_context import extract_code_context
from core.ai.manager import build_ai_provider_manager
from core.config.env_loader import load_environment
from core.registry.plugin_registry import PluginRegistry
from core.orchestration.orchestrator import ScanOrchestrator
from core.events.event_bus import EventBus
from core.risk.prioritization_engine import recommend_fixes, recommend_fixes_with_ai
from core.storage.storage_manager import StorageManager
from scanners.snyk.plugin import SnykPlugin
from scanners.semgrep.plugin import SemgrepPlugin

load_environment()

app = typer.Typer()


def build_registry() -> PluginRegistry:
    registry = PluginRegistry()
    registry.register(SnykPlugin())
    registry.register(SemgrepPlugin())
    return registry


@app.command()
def discover(path: str = '.'):
    """Discover application artifacts in a local repository."""
    registry = build_registry()
    discoverable = [plugin for plugin in registry.enabled('discovery')]
    results = []
    for plugin in discoverable:
        results.extend(plugin.discover(path))
    typer.echo(json.dumps(sorted(set(results)), indent=2))


@app.command()
def scan(
    target: str = typer.Argument(
        '.',
        help='Target path to scan.',
    ),
    plugin: Optional[str] = None,
    use_ai: bool = False,
    provider: Optional[str] = None,
    code_path: Optional[str] = typer.Option(
        None,
        help='Optional path to source code for AI effort estimation. Defaults to scan target.',
    ),
    snyk_org: Optional[str] = None,
    snyk_repo: Optional[str] = None,
):
    """Run enabled scanner plugins against a target."""
    registry = build_registry()
    if plugin:
        selected = registry.get(plugin)
        if selected is None:
            raise typer.BadParameter(f"Unknown plugin: {plugin}")
        if not getattr(selected, 'enabled', True):
            raise typer.BadParameter(f"Plugin {plugin} is disabled")
        registry = PluginRegistry()
        registry.register(selected)

    orchestrator = ScanOrchestrator(registry, EventBus())
    # Propagate Snyk org/repo scope to the environment for the Snyk plugin
    if snyk_org:
        import os

        os.environ['SNYK_ORG'] = snyk_org
    if snyk_repo:
        import os

        os.environ['SNYK_REPO'] = snyk_repo
    results = orchestrator.run(target)
    findings = [f for f in results.get('findings', [])]

    storage = StorageManager()
    if findings:
        from core.models.finding import Finding
        parsed_findings = [Finding.parse_obj(item) for item in findings]
        storage.save_findings(parsed_findings)

    ai_results = None
    fixes = []
    if use_ai and findings:
        from core.models.finding import Finding
        parsed_findings = [Finding.parse_obj(item) for item in findings]
        code_context = extract_code_context(code_path or target)
        ai_results = recommend_fixes_with_ai(
            parsed_findings,
            provider_name=provider,
            code_context=code_context,
        )
    elif findings:
        from core.models.finding import Finding
        parsed_findings = [Finding.parse_obj(item) for item in findings]
        fixes = recommend_fixes(parsed_findings)

    output = {
        'results': results,
        'recommendations': ai_results if use_ai else [fix.dict() for fix in fixes],
        'stored': len(findings),
    }
    if use_ai:
        output['ai_provider'] = provider or 'auto'
    typer.echo(json.dumps(output, indent=2))


@app.command('list-findings')
def list_findings(application_id: Optional[str] = None):
    """List findings stored in the local database."""
    storage = StorageManager()
    findings = storage.load_findings(application_id) if application_id else storage.list_findings()
    typer.echo(json.dumps([finding.dict() for finding in findings], indent=2))


@app.command('reprioritize')
def reprioritize(
    application_id: Optional[str] = None,
    use_ai: bool = False,
    provider: Optional[str] = None,
    code_path: Optional[str] = typer.Option(
        None,
        help='Optional path to source code for AI effort estimation when reprioritizing stored findings.',
    ),
):
    """Re-run prioritization on stored findings."""
    storage = StorageManager()
    findings = storage.load_findings(application_id) if application_id else storage.list_findings()
    raw_findings = [finding.dict() for finding in findings]
    if use_ai:
        from core.models.finding import Finding
        parsed_findings = [Finding.parse_obj(item) for item in raw_findings]
        code_context = extract_code_context(code_path or '.')
        recommendations = recommend_fixes_with_ai(
            parsed_findings,
            provider_name=provider,
            code_context=code_context,
        )
    else:
        recommendations = [fix.dict() for fix in recommend_fixes(findings)]
    typer.echo(json.dumps({'findings': raw_findings, 'recommendations': recommendations}, indent=2))


@app.command('map')
def map_application(target: str = '.'):
    """Build a minimal application model for a target repository."""
    registry = build_registry()
    orchestrator = ScanOrchestrator(registry, EventBus())
    results = orchestrator.run(target)
    typer.echo(json.dumps(results['application'], indent=2))


if __name__ == '__main__':
    app()
