
from typing import List
import os

from core.config.env_loader import get_env_variable
from core.plugins.base import ScannerPlugin
from core.models.finding import Finding
import shutil
import subprocess
import json
import requests

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
                if all_items:
                    for i, v in enumerate(all_items[:200]):
                        sev = v.get('severity') or v.get('impact') or 'medium'
                        title = v.get('title') or v.get('name') or v.get('id')
                        description = v.get('description') or v.get('message') or ''
                        evidence = []
                        if isinstance(v.get('from'), list):
                            evidence = [" -> ".join(v.get('from'))]
                        elif isinstance(v.get('location'), dict):
                            path = v.get('location', {}).get('path')
                            if path:
                                evidence = [path]
                        elif v.get('packageName'):
                            evidence = [v.get('packageName')]
                        findings.append(
                            Finding(
                                id=f"snyk-api-{i}",
                                source='snyk',
                                severity=str(sev),
                                title=str(title),
                                description=description,
                                evidence=evidence,
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
                try:
                    data = json.loads(out) if out else {}
                except json.JSONDecodeError:
                    data = {}

                def extract_list(d: dict):
                    for k in ('vulnerabilities', 'issues', 'results', 'vulns'):
                        if isinstance(d.get(k), list):
                            return d.get(k)
                    # some Snyk outputs nest results under 'path' or are empty
                    return []

                items1 = extract_list(data)
                if items1:
                    all_items.extend(items1)

                # Run `snyk code test <target> --json` for Snyk Code issues
                proc2 = subprocess.run([snyk_bin, 'code', 'test', target, '--json'], capture_output=True, text=True, timeout=60)
                out2 = proc2.stdout or proc2.stderr
                try:
                    data2 = json.loads(out2) if out2 else {}
                except json.JSONDecodeError:
                    data2 = {}

                items2 = extract_list(data2)
                if items2:
                    all_items.extend(items2)

                # If we found combined items, convert to Findngs
                findings: List[Finding] = []
                if all_items:
                    for i, v in enumerate(all_items[:200]):
                        # normalize common fields
                        sev = v.get('severity') or v.get('impact') or 'medium'
                        title = v.get('title') or v.get('message') or v.get('id') or v.get('name')
                        description = v.get('description') or v.get('message') or ''
                        evidence = []
                        if isinstance(v.get('from'), list):
                            evidence = [" -> ".join(v.get('from'))]
                        elif isinstance(v.get('location'), dict):
                            path = v.get('location', {}).get('path')
                            if path:
                                evidence = [path]
                        elif v.get('packageName'):
                            evidence = [v.get('packageName')]
                        findings.append(
                            Finding(
                                id=f"snyk-{target}-{i}",
                                source='snyk',
                                severity=str(sev),
                                title=str(title),
                                description=description,
                                evidence=evidence,
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
            except Exception:
                return []

        # No API token and no local CLI available — return empty results
        return []
