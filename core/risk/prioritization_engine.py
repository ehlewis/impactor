import re
from typing import List, Dict, Optional

from core.models.finding import Finding
from core.models.fix_recommendation import FixRecommendation

SEVERITY_WEIGHT = {
    'critical': 5,
    'high': 4,
    'medium': 3,
    'low': 2,
    'info': 1,
}

EFFORT_SCORE = {
    'low': 1,
    'medium': 2,
    'high': 3,
}

PRIORITY_LABELS = ['Critical', 'High', 'Medium', 'Low']


def normalize_severity(severity: str) -> str:
    return severity.strip().lower() if severity else 'info'


def compute_risk_score(finding: Finding) -> float:
    severity = normalize_severity(finding.severity)
    base = SEVERITY_WEIGHT.get(severity, 1)
    multiplier = 1.0
    if is_test_file_credential_finding(finding) or is_low_context_finding(finding):
        return max(1.0, base * 0.35)
    if 'public exploit' in finding.description.lower() or 'public exploit' in ' '.join(finding.evidence).lower():
        multiplier += 0.5
    if 'internet' in finding.description.lower() or 'internet' in ' '.join(finding.evidence).lower():
        multiplier += 0.25
    return base * multiplier


TEST_FILE_PATTERNS = ['test/', '/test', 'tests/', '/tests', 'spec/', '/spec', 'fixture', 'mock']
LOW_CONTEXT_FILE_PATTERNS = [
    'examples/', '/examples', 'sample', 'template', 'generated', 'node_modules', 'vendor/', 'build/', 'dist/',
    'docs/', 'readme', '.env.example', '.sample', '.template', 'docker-compose', 'dockerfile', 'fixtures/',
]
CREDENTIAL_KEYWORDS = ['password', 'secret', 'credential', 'apikey', 'api key', 'token']
SAMPLE_KEYWORDS = ['example', 'sample', 'template', 'generated', 'demo', 'documentation', 'docs', 'fixture', 'mock']


def is_test_file_credential_finding(finding: Finding) -> bool:
    evidence_text = ' '.join(finding.evidence).lower()
    title = finding.title.lower()
    description = finding.description.lower()
    has_test_path = any(pattern in evidence_text for pattern in TEST_FILE_PATTERNS)
    has_credential_keyword = any(keyword in evidence_text or keyword in title or keyword in description for keyword in CREDENTIAL_KEYWORDS)
    return has_test_path and has_credential_keyword


def is_low_context_finding(finding: Finding) -> bool:
    evidence_text = ' '.join(finding.evidence).lower()
    title = finding.title.lower()
    description = finding.description.lower()
    if any(pattern in evidence_text for pattern in LOW_CONTEXT_FILE_PATTERNS):
        return True
    if any(keyword in title or keyword in description for keyword in SAMPLE_KEYWORDS):
        return True
    return False


def determine_effort(finding: Finding) -> str:
    if is_test_file_credential_finding(finding) or is_low_context_finding(finding):
        return 'low'

    title = finding.title.lower()
    if 'sql injection' in title or 'remote code execution' in title:
        return 'high'
    if 'cross-site' in title or 'xss' in title:
        return 'medium'
    return 'low'


def determine_priority(score: float) -> str:
    if score >= 6.0:
        return 'Critical'
    if score >= 5.0:
        return 'High'
    if score >= 3.5:
        return 'Medium'
    return 'Low'


def _extract_evidence_path(value: str) -> str:
    if ':' in value:
        return value.split(':', 1)[0]
    return value


def _extract_shared_code_anchors(finding: Finding) -> set[str]:
    anchors: set[str] = set()
    if finding.path:
        anchors.add(finding.path)
    for item in finding.evidence:
        path_value = _extract_evidence_path(item)
        if path_value:
            anchors.add(path_value)
    return anchors


def _group_findings_by_shared_code(findings: List[Finding]) -> List[List[Finding]]:
    anchor_map: Dict[str, List[Finding]] = {}
    for finding in findings:
        for anchor in _extract_shared_code_anchors(finding):
            anchor_map.setdefault(anchor, []).append(finding)

    groups: List[List[Finding]] = []
    seen: set[tuple[str, ...]] = set()
    for group in anchor_map.values():
        if len(group) < 2:
            continue
        key = tuple(sorted(f.id for f in group))
        if key in seen:
            continue
        seen.add(key)
        groups.append(group)

    return groups


def _normalize_recommendation_id(value: str) -> str:
    clean = re.sub(r'[^a-z0-9]+', '-', value.strip().lower())
    return clean.strip('-')[:60]


def _common_shared_code_evidence(group: List[Finding]) -> List[str]:
    evidence_sets = [set(f.evidence) for f in group if f.evidence]
    shared_code: set[str] = set()

    if evidence_sets:
        shared_evidence = set.intersection(*evidence_sets)
        if shared_evidence:
            shared_code.update(shared_evidence)

        common_paths = [set(_extract_evidence_path(item) for item in evidence) for evidence in evidence_sets]
        shared_paths = set.intersection(*common_paths) if common_paths else set()
        for path in shared_paths:
            path_specific = {
                item
                for finding in group
                for item in finding.evidence
                if _extract_evidence_path(item) == path
            }
            if path_specific:
                shared_code.update(path_specific)
            else:
                shared_code.add(path)

    path_values = [f.path for f in group if f.path]
    if len(path_values) == len(group):
        shared_code.update(path_values)

    return sorted(shared_code)


def recommend_fixes(findings: List[Finding]) -> List[FixRecommendation]:
    groups = _group_findings_by_shared_code(findings)
    grouped_ids = {finding.id for group in groups for finding in group}
    singletons = [finding for finding in findings if finding.id not in grouped_ids]

    recommendations: List[FixRecommendation] = []
    for group in groups:
        impacted_ids = [finding.id for finding in group]
        total_score = sum(compute_risk_score(f) for f in group)
        avg_score = total_score / len(group)
        if any(is_test_file_credential_finding(f) or is_low_context_finding(f) for f in group):
            effort = 'low'
        else:
            effort = 'low' if all(determine_effort(f) == 'low' for f in group) else (
                'medium' if any(determine_effort(f) == 'medium' for f in group) else 'high'
            )
        if any(is_test_file_credential_finding(f) or is_low_context_finding(f) for f in group):
            priority = 'Low'
            remediation = (
                'Review the finding in context. If it comes from sample, generated, or test scaffolding files, it is likely a low-priority false positive and may not require production remediation.'
            )
        else:
            priority = determine_priority(avg_score)
            remediation = (
                'Apply a small code change to validate inputs and sanitize user-controlled data, which will remediate multiple findings.'
                if len(group) > 1
                else 'Remediate the specific finding with a targeted patch.'
            )
        shared_code = _common_shared_code_evidence(group)
        title = f'Fix shared code at {shared_code[0]}' if shared_code else f'Fix {group[0].title}'
        recommendations.append(
            FixRecommendation(
                id=f'fix-{_normalize_recommendation_id(title)}',
                title=title,
                description=f'Remediate {len(group)} related finding(s) by fixing the shared root cause.',
                impacted_findings=impacted_ids,
                effort=effort,
                expected_risk_reduction=min(1.0, total_score / (len(findings) * 2)),
                priority=priority,
                remediation=remediation,
                shared_code=shared_code,
            )
        )

    for finding in singletons:
        total_score = compute_risk_score(finding)
        effort = 'low' if is_test_file_credential_finding(finding) or is_low_context_finding(finding) else determine_effort(finding)
        priority = 'Low' if is_test_file_credential_finding(finding) or is_low_context_finding(finding) else determine_priority(total_score)
        remediation = (
            'Review the finding in context. If it comes from sample, generated, or test scaffolding files, it is likely a low-priority false positive and may not require production remediation.'
            if priority == 'Low' and (is_test_file_credential_finding(finding) or is_low_context_finding(finding))
            else 'Remediate the specific finding with a targeted patch.'
        )
        shared_code = _common_shared_code_evidence([finding])
        title = f'Fix {finding.title}'
        recommendations.append(
            FixRecommendation(
                id=f'fix-{_normalize_recommendation_id(title)}',
                title=title,
                description='Remediate this finding by fixing the identified code issue.',
                impacted_findings=[finding.id],
                effort=effort,
                expected_risk_reduction=min(1.0, total_score / (len(findings) * 2)),
                priority=priority,
                remediation=remediation,
                shared_code=shared_code,
            )
        )

    return sorted(recommendations, key=lambda rec: (-SEVERITY_WEIGHT.get(rec.priority.lower(), 0), rec.effort))


def recommend_fixes_with_ai(
    findings: List[Finding],
    provider_name: Optional[str] = None,
    code_context: Optional[Dict[str, str]] = None,
) -> Dict:
    """Compute local deterministic recommendations and optionally enrich them with AI context."""
    deterministic_recommendations = recommend_fixes(findings)
    from core.ai.manager import build_ai_provider_manager

    manager = build_ai_provider_manager()
    raw_findings = [finding.dict() for finding in findings]
    raw_recommendations = [fix.dict() for fix in deterministic_recommendations]
    try:
        ai_enrichment = manager.enrich_recommendations(
            raw_findings,
            raw_recommendations,
            provider_name=provider_name,
            code_context=code_context,
        )
    except ValueError as exc:
        ai_enrichment = {'error': str(exc)}

    return {
        'provider': ai_enrichment.get('provider', provider_name or 'auto'),
        'deterministic': raw_recommendations,
        'ai_enrichment': ai_enrichment,
    }
