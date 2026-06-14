# Impcator Framework

Impcator is a modular Application Security Exposure Management platform focused on application-centric discovery, correlation, and explainable risk.

## Core Platform Modules

- **Discovery Engine**: discovers repositories, applications, manifests, infrastructure definitions, and deployment artifacts.
- **Application Model**: represents applications, repositories, deployment contexts, and business-critical metadata.
- **Manifest System**: supports `impcator.yaml` for manual application definitions, business context, deployments, and critical data.
- **Scanner Framework**: plugin-driven SCA/SAST/DAST integration with local-first execution.
- **ACE (Application Context Engine)**: captures business domains, flows, data paths, and security boundaries.
- **AME (Application Mapping Engine)**: maps applications to assets with confidence and evidence.
- **Asset Framework**: represents infrastructure assets and providers such as Tenable.
 - **Asset Framework**: represents infrastructure assets and providers.
- **Attack Surface Map Generator**: builds graph models of entry points, boundaries, services, and sensitive data.
- **Attack Path Generator**: generates realistic attack chains and exploit paths.
- **Correlation Engine**: links repositories, applications, deployments, assets, vulnerabilities, and attack paths.
- **Risk Engine**: deterministic scoring from severity, exposure, exploitability, and business impact.
- **Runtime Context**: future optional providers for alerts, exploitation, and behavioral context.
- **Storage Layer**: provider-based persistence with SQLite as the default local store.

## Manifest System

The manifest system supports `impcator.yaml` as the authoritative source for:

- application definitions
- business context
- deployment descriptions
- critical data classification
- discovery overrides

Priority order:

1. Manual manifest
2. Discovery
3. AI inference

## Plugin First

All external integrations are plugins. The core platform contains no tool-specific logic.

Supported plugin categories include:

- discovery
- scanner
- asset provider
- runtime context

Example plugin integrations:

- Snyk, Semgrep, CodeQL, OWASP ZAP
- Azure, AWS, Kubernetes
- GitHub, GitLab, Bitbucket

## CLI Usage

The `scan` command accepts the scan target as a positional argument:

```bash
impcator discover .
impcator scan /path/to/repository
impcator scan . --use-ai
impcator scan . --use-ai --code-path src/
impcator scan . --snyk-org my-org-id --snyk-repo my-repo-name
impcator map .
impcator list-findings
impcator list-findings --sort-by priority --no-descending
impcator list-findings --sort-by risk --limit 20
impcator list-findings --application-id claims-platform --sort-by effort --limit 10
impcator list-findings --with-recommendations
impcator list-findings --with-recommendations --sort-by expected-risk-reduction --limit 10
impcator reprioritize
impcator reprioritize --use-ai --provider openai
```

## Stored Findings and Reanalysis

Scan results are persisted to a local SQLite database so findings can be reviewed and re-analyzed later.

- `list-findings` lists findings stored in the database. It supports sorting by `risk`, `effort`, or `priority`, and can return only the first `X` results.
- `list-findings --with-recommendations` shows findings grouped by root cause with actionable fix recommendations. Each recommendation includes:
  - **impacted_findings**: list of finding IDs affected by this root cause
  - **effort**: estimated effort to fix (low, medium, high)
  - **priority**: assessed priority (Critical, High, Medium, Low)
  - **remediation**: specific guidance on how to fix the root cause
  - **shared_code**: common code locations across related findings
  - **expected_risk_reduction**: estimated risk reduction if the recommendation is implemented
  - Use `--sort-by expected-risk-reduction` to sort recommendations by their impact (highest risk reduction first)
- `reprioritize` re-runs prioritization on stored findings.
- `reprioritize --use-ai` uses the selected AI provider to produce fix recommendations.

### Data Storage

The default storage layer is SQLite. Findings are stored in a local database file and can be queried by application or reprocessed for updated prioritization.

### Persistence benefits

- preserve scan history
- compare current versus past findings
- re-run prioritization without rerunning scans
- support future analytics and attack path correlation

## Local First

Impcator is designed to evaluate local artifacts first, with prioritized data sources:

1. Static analysis
2. Manifest data
3. Documentation
4. Infrastructure definitions
5. AI enrichment

## Explainable Results

Every decision and mapping should include evidence for why it exists, such as:

- README.md
- deployment manifests
- pipeline definitions
- Tenable assets
- scanner findings

## Getting Started

### Prerequisites

- Python 3.11+ (the repository includes a `.venv` virtual environment)
- Git
- Optional: API credentials for external scanner or asset plugins

### Install

```bash
cd /Users/evanlewis/repos/impactor
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

This project also requires `setuptools` and `wheel` for editable install support. They are pinned in `requirements.txt`.

Or install `impcator` into your environment for convenient CLI usage:

```bash
pip install -e .
```

This exposes the `impcator` console command (installed entry point) so you can run:

```bash
impcator scan . --use-ai
```

### Run the CLI

```bash
python cli/main.py discover .
python cli/main.py scan .
python cli/main.py map
```

### API key setup

The current skeleton uses local plugin placeholders and does not require API keys to run the sample CLI commands. When you add real integrations, configure credentials through environment variables or a manifest.

Recommended environment variables for common integrations:

- `SNYK_TOKEN` or `SNYK_API_TOKEN`
 - `TENABLE_API_KEY`  # optional, removed from default focus
- `AZURE_CLIENT_ID`, `AZURE_TENANT_ID`, `AZURE_CLIENT_SECRET`
- `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN`
- `GITHUB_TOKEN`
- `GITLAB_TOKEN`
- `OPENAI_API_KEY`
- `OPENAI_MODEL`
- `OPENAI_API_BASE`
- `OLLAMA_API_BASE`
- `OLLAMA_MODEL`
- `OLLAMA_API_KEY`

Example using `.env` or your shell:

```bash
export SNYK_TOKEN="your-snyk-token"
export OPENAI_API_KEY="your-openai-api-key"
export OLLAMA_MODEL="your-ollama-model"
export OLLAMA_API_BASE="http://localhost:11434"
```

### AI provider selection

The scan command supports optional AI-based prioritization via provider selection. You can also provide a code path for the AI to inspect source files, infer function behavior, and improve effort estimation:

```bash
python cli/main.py scan . --use-ai
python cli/main.py scan . --use-ai --provider openai
python cli/main.py scan . --use-ai --provider ollama
python cli/main.py scan . --use-ai --provider local-stub
python cli/main.py scan . --use-ai --code-path src/
```

If you have the Snyk CLI installed locally, Impcator will use it automatically when no `SNYK_TOKEN` is configured. This is exposed as the `snyk-cli` scanner plugin. Install Snyk locally with:

```bash
npm install -g snyk
# then authenticate if you have an account:
snyk auth
```

Snyk API integration

If you prefer API-backed Snyk integration, set `SNYK_TOKEN` and optionally scope scans to an organization and project (repo) using the CLI flags. This is exposed as the `snyk-api` scanner plugin and is selected automatically whenever `SNYK_TOKEN` is configured:

```bash
export SNYK_TOKEN="your-snyk-api-token"
python cli/main.py scan . --snyk-org my-org-id --snyk-repo my-repo-name
```

Notes:
- `--snyk-org` should be the Snyk organization identifier. When provided, Impcator will request projects from that org and fetch issues via the Snyk API.
- `--snyk-repo` filters projects within the org by name; provide the repo/project name to limit results.

Impcator computes deterministic recommendations locally first and uses AI mainly to enrich those recommendations with context from the code. If `--code-path` is omitted, the scan target is used for code context extraction.

AI prioritization now favors contextual reasoning for broader SAST false-positive patterns. For example, findings can be downgraded when they are detected in:

- test, spec, fixture, or mock files containing hardcoded credentials
- sample, example, or generated source artifacts
- documentation, build output, or template files

The output should classify those findings as low priority when they appear to be benign or intentionally non-production content. You can also apply AI prioritization to stored findings with `reprioritize` and local code context:

```bash
python cli/main.py reprioritize --use-ai --provider ollama --code-path src/
```

### Override order

The loader supports both `.env` and `.env.local` files.

- `.env` is loaded first
- `.env.local` is loaded second and overrides `.env`

Use `.env.local` for machine-specific or private overrides that should not be committed.

### Optional manifest

Create `impcator.yaml` to define applications, business context, deployments, and discovery overrides:

```yaml
version: '1.0'
applications:
  - id: claims-platform
    name: Claims Platform
    description: "Claims processing application"
    business_context:
      owner: "Insurance"
      criticality: "high"
    deployments:
      - environment: production
        cluster: claims-prod
    critical_data:
      - PII
```

Place `impcator.yaml` in the repository root or a parent directory and the manifest loader will discover it automatically.
