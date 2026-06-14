
from typing import Any, Dict, List
import os

from core.config.env_loader import get_env_variable
from core.plugins.base import ScannerPlugin
from core.models.finding import Finding
import shutil
import subprocess
import json
import requests


def _is_issue_like(item: Any) -> bool:
    return isinstance(item, dict) and any(
        key in item for key in (
            'id', 'issueId', 'title', 'severity', 'message', 'name',
            'packageName', 'from', 'location', 'path', 'language', 'issue',
        )
    )


def _collect_issue_lists(data: Any) -> List[Dict[str, Any]]:
    issues: List[Dict[str, Any]] = []
    if isinstance(data, dict):
        for key in ('issues', 'vulnerabilities', 'results', 'vulns'):
            value = data.get(key)
            if isinstance(value, list):
                issues.extend([item for item in value if isinstance(item, dict)])
    elif isinstance(data, list):
        if all(isinstance(item, dict) for item in data) and any(_is_issue_like(item) for item in data):
            issues.extend(data)
    return issues


def _find_nested_issue_lists(data: Any) -> List[Dict[str, Any]]:
    issues: List[Dict[str, Any]] = []
    if isinstance(data, dict):
        for value in data.values():
            if isinstance(value, list):
                if all(isinstance(item, dict) for item in value) and any(_is_issue_like(item) for item in value):
                    issues.extend(value)
                else:
                    for item in value:
                        issues.extend(_find_nested_issue_lists(item))
            elif isinstance(value, dict):
                issues.extend(_find_nested_issue_lists(value))
    elif isinstance(data, list):
        for item in data:
            issues.extend(_find_nested_issue_lists(item))
    return issues


def _extract_snyk_issues(data: Any) -> List[Dict[str, Any]]:
    if not data:
        return []
    issues = _collect_issue_lists(data)
    if issues:
        return issues
    return _find_nested_issue_lists(data)


def _load_json_safe(raw: str) -> Any:
    try:
        return json.loads(raw) if raw else {}
    except json.JSONDecodeError:
        return {}


def _normalize_text_field(value: Any) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, dict):
        for key in ('text', 'message', 'description', 'name'):
            if isinstance(value.get(key), str):
                return value.get(key)
        flattened = [str(v) for v in value.values() if isinstance(v, (str, int, float))]
        return ' '.join(flattened)
    if isinstance(value, list):
        return ' '.join(str(item) for item in value if isinstance(item, (str, int, float)))
    return str(value) if value is not None else ''


def _extract_snyk_cli_error(data: Any, target: str, command: str) -> str:
    if not isinstance(data, dict):
        return ''

    if data.get('ok') is False:
        if _extract_snyk_issues(data):
            return ''
        if data.get('error'):
            if isinstance(data.get('error'), dict):
                return f"{command} failed for {target}: {data.get('error').get('message', data.get('error'))}"
            return f"{command} failed for {target}: {data.get('error')}"
        if data.get('message'):
            return f"{command} failed for {target}: {data.get('message')}"
        if data.get('reason'):
            return f"{command} failed for {target}: {data.get('reason')}"
        if data.get('errors'):
            errors = data.get('errors')
            if isinstance(errors, list) and errors:
                first_error = errors[0]
                if isinstance(first_error, dict):
                    return f"{command} failed for {target}: {first_error.get('message', first_error)}"
                return f"{command} failed for {target}: {first_error}"
        return f"{command} failed for {target} with unknown error"

    if data.get('error'):
        if isinstance(data.get('error'), dict):
            return f"{command} failed for {target}: {data.get('error').get('message', data.get('error'))}"
        return f"{command} failed for {target}: {data.get('error')}"
    if data.get('message') and 'failed' in str(data.get('message')).lower():
        return f"{command} failed for {target}: {data.get('message')}"
    return ''


def _ensure_snyk_subprocess_success(proc: subprocess.CompletedProcess, data: Any, target: str, command: str) -> None:
    error_message = _extract_snyk_cli_error(data, target, command)
    if error_message:
        raise SystemExit(error_message)
    if proc.returncode != 0 and not data:
        raise SystemExit(f"{command} failed for {target}: subprocess exited with code {proc.returncode} and no JSON output")


class SnykPlugin(ScannerPlugin):
    name = 'snyk'
    version = '0.1.0'

    def scan(self, target: str) -> List[Finding]:
        # Prefer API token-based integrations when configured
        api_token = get_env_variable('SNYK_TOKEN')
        snyk_org = os.getenv('SNYK_ORG')
        snyk_repo = os.getenv('SNYK_REPO')
        api_base = os.getenv('SNYK_API_BASE', 'https://snyk.io/api/v1')
        if api_token:
            # Try API-backed integration when token and org are provided
            headers = {'Authorization': f'token {api_token}', 'Content-Type': 'application/json'}
            try:
                projects = []
                if snyk_org:
                    projects_url = f"{api_base}/org/{snyk_org}/projects"
                    r = requests.get(projects_url, headers=headers, timeout=30)
                    if r.status_code == 200:
                        data = r.json()
                        projects = data.get('projects') or data.get('projects', []) or data.get('projects', [])
                # If org not provided or projects empty, try to list org projects across orgs (best-effort)
                if not projects and snyk_repo:
                    # No reliable cross-org listing implemented; fall back to CLI
                    projects = []

                all_items = []
                for p in projects:
                    project_id = p.get('id') or p.get('uuid') or p.get('projectId')
                    if not project_id:
                        continue
                    # Optionally filter by repo/name
                    name = p.get('name') or p.get('id') or ''
                    if snyk_repo and snyk_repo not in name:
                        continue
                    issues_url = f"{api_base}/org/{snyk_org}/project/{project_id}/issues"
                    r2 = requests.get(issues_url, headers=headers, timeout=30)
                    if r2.status_code == 200:
                        data2 = r2.json()
                        # collect common issue lists
                        for k in ('issues', 'vulnerabilities', 'vulns', 'results'):
                            if isinstance(data2.get(k), list):
                                all_items.extend(data2.get(k))

                # Convert API-sourced items into Findings
                findings: List[Finding] = []
                for i, v in enumerate(all_items):
                    if not isinstance(v, dict):
                        continue
                    sev = _normalize_text_field(v.get('severity') or v.get('impact') or 'medium')
                    title = _normalize_text_field(v.get('title') or v.get('name') or v.get('id') or v.get('issueId'))
                    description = _normalize_text_field(v.get('description') or v.get('message') or '')
                    evidence = []
                    if isinstance(v.get('from'), list):
                        evidence = [" -> ".join(v.get('from'))]
                    elif isinstance(v.get('location'), dict):
                        path = v.get('location', {}).get('path')
                        if path:
                            evidence = [path]
                    elif v.get('packageName'):
                        evidence = [v.get('packageName')]
                    elif v.get('path'):
                        evidence = [v.get('path')]
                    findings.append(
                        Finding(
                            id=f"snyk-api-{i}",
                            source='snyk',
                            severity=str(sev),
                            title=str(title),
                            description=description,
                            evidence=evidence,
                            metadata={'raw': v},
                        )
                    )
                return findings
            except Exception:
                # Fall back to CLI if API path fails
                pass

        # If no API token, attempt to use the local `snyk` CLI if installed
        snyk_bin = shutil.which('snyk')
        if snyk_bin:
            try:
                all_items = []

                # Run `snyk test <target> --json`
                proc = subprocess.run([snyk_bin, 'test', target, '--json'], capture_output=True, text=True, timeout=60)
                out = proc.stdout or proc.stderr
                data = _load_json_safe(out)

                _ensure_snyk_subprocess_success(proc, data, target, 'snyk test')
                items1 = _extract_snyk_issues(data)
                if items1:
                    all_items.extend(items1)

                # Run `snyk code test <target> --json` for Snyk Code issues
                proc2 = subprocess.run([snyk_bin, 'code', 'test', target, '--json'], capture_output=True, text=True, timeout=None)
                out2 = proc2.stdout or proc2.stderr
                data2 = _load_json_safe(out2)

                _ensure_snyk_subprocess_success(proc2, data2, target, 'snyk code test')

                items2 = _extract_snyk_issues(data2)
                if items2:
                    all_items.extend(items2)

                # If we found combined items, convert to Findings
                findings: List[Finding] = []
                if all_items:
                    for i, v in enumerate(all_items):
                        if not isinstance(v, dict):
                            continue
                        # normalize common fields
                        sev = _normalize_text_field(v.get('severity') or v.get('impact') or 'medium')
                        title = _normalize_text_field(v.get('title') or v.get('message') or v.get('id') or v.get('name') or v.get('issueId'))
                        description = _normalize_text_field(v.get('description') or v.get('message') or '')
                        evidence = []
                        if isinstance(v.get('from'), list):
                            evidence = [" -> ".join(v.get('from'))]
                        elif isinstance(v.get('location'), dict):
                            path = v.get('location', {}).get('path')
                            if path:
                                evidence = [path]
                        elif v.get('packageName'):
                            evidence = [v.get('packageName')]
                        elif v.get('path'):
                            evidence = [v.get('path')]
                        findings.append(
                            Finding(
                                id=f"snyk-{target}-{i}",
                                source='snyk',
                                severity=str(sev),
                                title=str(title),
                                description=description,
                                evidence=evidence,
                                metadata={'raw': v},
                            )
                        )
                    return findings

                # If no items found but Snyk ran, return an info finding
                if proc.returncode == 0 or proc2.returncode == 0:
                    return [
                        Finding(
                            id=f'snyk-{target}-0',
                            source='snyk',
                            severity='info',
                            title='Snyk scan completed',
                            description='Snyk completed but produced no structured issues.',
                            evidence=[target],
                        )
                    ]
            except Exception as e:
                print(f"Error occurred while processing Snyk results for {target}: {e}")
                return []

        # No API token and no local CLI available — return empty results
        return []
