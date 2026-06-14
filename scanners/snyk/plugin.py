
from typing import Any, Dict, List
import hashlib
import os

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


def _normalize_issue_evidence(issue: Dict[str, Any]) -> List[str]:
    evidence: List[str] = []
    if isinstance(issue.get('from'), list):
        chain = [str(item) for item in issue.get('from') if item is not None]
        if chain:
            evidence.append(' -> '.join(chain))

    location = issue.get('location')
    if isinstance(location, dict):
        path = location.get('path')
        if path:
            lines = location.get('lines')
            if isinstance(lines, dict):
                begin = lines.get('begin')
                end = lines.get('end')
                if begin and end and begin != end:
                    evidence.append(f"{path}:{begin}-{end}")
                elif begin:
                    evidence.append(f"{path}:{begin}")
                else:
                    evidence.append(str(path))
            else:
                evidence.append(str(path))

    if not evidence and issue.get('path'):
        evidence.append(str(issue.get('path')))
    if not evidence and issue.get('packageName'):
        evidence.append(str(issue.get('packageName')))
    if not evidence and issue.get('package'):
        evidence.append(str(issue.get('package')))
    if not evidence and issue.get('moduleName'):
        evidence.append(str(issue.get('moduleName')))

    return evidence


def _extract_snyk_location_path(location: Any) -> str:
    if not isinstance(location, dict):
        return ''

    path = location.get('path')
    if path:
        return str(path)

    physical = location.get('physicalLocation')
    if isinstance(physical, dict):
        artifact = physical.get('artifactLocation')
        if isinstance(artifact, dict):
            uri = artifact.get('uri')
            if uri:
                return str(uri)

    artifact = location.get('artifactLocation')
    if isinstance(artifact, dict):
        uri = artifact.get('uri')
        if uri:
            return str(uri)

    return ''


def _extract_snyk_path(issue: Dict[str, Any]) -> str:
    for source in ('location', 'physicalLocation'):
        path = _extract_snyk_location_path(issue.get(source))
        if path:
            return path

    locations = issue.get('locations')
    if isinstance(locations, list):
        for entry in locations:
            if not isinstance(entry, dict):
                continue
            path = _extract_snyk_location_path(entry.get('physicalLocation') or entry.get('location'))
            if path:
                return path

    code_flows = issue.get('codeFlows')
    if isinstance(code_flows, list):
        for flow in code_flows:
            if not isinstance(flow, dict):
                continue
            thread_flows = flow.get('threadFlows')
            if isinstance(thread_flows, list):
                for thread in thread_flows:
                    if not isinstance(thread, dict):
                        continue
                    locations = thread.get('locations')
                    if isinstance(locations, list):
                        for location_entry in locations:
                            if not isinstance(location_entry, dict):
                                continue
                            path = _extract_snyk_location_path(location_entry.get('location'))
                            if path:
                                return path

    if issue.get('path'):
        return str(issue.get('path'))
    return ''


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


def _build_short_finding_id(prefix: str, target: str, title: str, path: str) -> str:
    value = f"{prefix}:{target}:{title}:{path}"
    digest = hashlib.sha256(value.encode('utf-8')).hexdigest()[:10]
    return f"{prefix}-{digest}"


def _build_snyk_findings(items: List[Dict[str, Any]], prefix: str, target: str) -> List[Finding]:
    findings: List[Finding] = []
    for item in items:
        if not isinstance(item, dict):
            continue
        sev = _normalize_text_field(item.get('severity') or item.get('impact') or 'medium')
        title = _normalize_text_field(item.get('title') or item.get('name') or item.get('message') or item.get('id') or item.get('issueId'))
        description = _normalize_text_field(item.get('description') or item.get('message') or '')
        evidence = _normalize_issue_evidence(item)
        path_value = _extract_snyk_path(item)
        finding_id = _build_short_finding_id(prefix, target, title, path_value)
        findings.append(
            Finding(
                id=finding_id,
                source='snyk',
                severity=str(sev),
                title=str(title),
                description=description,
                path=path_value,
                evidence=evidence,
                metadata={'raw': item},
            )
        )
    return findings


class SnykAPIPlugin(ScannerPlugin):
    name = 'snyk-api'
    version = '0.1.0'

    @property
    def enabled(self) -> bool:
        return bool(os.getenv('SNYK_TOKEN'))

    def scan(self, target: str) -> List[Finding]:
        api_token = os.getenv('SNYK_TOKEN')
        snyk_org = os.getenv('SNYK_ORG')
        snyk_repo = os.getenv('SNYK_REPO')
        api_base = os.getenv('SNYK_API_BASE', 'https://snyk.io/api/v1')

        headers = {'Authorization': f'token {api_token}', 'Content-Type': 'application/json'}
        projects = []
        if snyk_org:
            projects_url = f"{api_base}/org/{snyk_org}/projects"
            r = requests.get(projects_url, headers=headers, timeout=30)
            if r.status_code == 200:
                data = r.json()
                projects = data.get('projects') or []

        if not projects and snyk_repo:
            return []

        all_items: List[Dict[str, Any]] = []
        for p in projects:
            project_id = p.get('id') or p.get('uuid') or p.get('projectId')
            if not project_id:
                continue
            name = p.get('name') or p.get('id') or ''
            if snyk_repo and snyk_repo not in name:
                continue
            issues_url = f"{api_base}/org/{snyk_org}/project/{project_id}/issues"
            r2 = requests.get(issues_url, headers=headers, timeout=30)
            if r2.status_code == 200:
                data2 = r2.json()
                for k in ('issues', 'vulnerabilities', 'vulns', 'results'):
                    if isinstance(data2.get(k), list):
                        all_items.extend(data2.get(k))

        return _build_snyk_findings(all_items, 'snyk-api', target)


class SnykCLIPlugin(ScannerPlugin):
    name = 'snyk-cli'
    version = '0.1.0'

    @property
    def enabled(self) -> bool:
        return bool(shutil.which('snyk')) and not bool(os.getenv('SNYK_TOKEN'))

    def scan(self, target: str) -> List[Finding]:
        snyk_bin = shutil.which('snyk')
        if not snyk_bin:
            return []
        
        print(f"Running Snyk CLI scan on {target} using {snyk_bin}")

        proc = subprocess.run([snyk_bin, 'test', target, '--json'], capture_output=True, text=True, timeout=60)
        out = proc.stdout or proc.stderr
        data = _load_json_safe(out)
        _ensure_snyk_subprocess_success(proc, data, target, 'snyk test')
        all_items: List[Dict[str, Any]] = _extract_snyk_issues(data)

        proc2 = subprocess.run([snyk_bin, 'code', 'test', target, '--json'], capture_output=True, text=True, timeout=None)
        out2 = proc2.stdout or proc2.stderr
        data2 = _load_json_safe(out2)
        _ensure_snyk_subprocess_success(proc2, data2, target, 'snyk code test')
        all_items.extend(_extract_snyk_issues(data2))

        findings = _build_snyk_findings(all_items, 'snyk', target)
        if findings:
            return findings

        if proc.returncode == 0 or proc2.returncode == 0:
            return [
                Finding(
                    id=f'snyk-{target}-0',
                    source='snyk',
                    severity='info',
                    title='Snyk scan completed',
                    description='Snyk completed but produced no structured issues.',
                    path=target,
                    evidence=[target],
                )
            ]
        return []
