# SBOM Risk Analyzer

SBOM Risk Analyzer is an offline-first Python CLI for mapping a software project's dependencies, identifying supply-chain risk, and producing remediation-ready reports. It accepts project directories, package manifests, lockfiles, and CycloneDX/SPDX JSON SBOMs.

It builds a directed dependency graph with NetworkX, resolves direct and transitive relationships where lockfile data permits, matches vulnerabilities from a local OSV cache, evaluates maintenance and license-policy signals, and produces a composite 0–100 threat score.

## Highlights

- Scan one or many projects independently from the terminal.
- Parse npm (package-lock.json, yarn.lock), PyPI (poetry.lock, Pipfile.lock, requirements.txt), Maven (pom.xml), Go (go.mod, go.sum), Rust (Cargo.lock), Ruby (Gemfile.lock), PHP (composer.lock), CycloneDX JSON, and SPDX JSON inputs.
- Sync OSV public advisory archives into a local SQLite cache; normal vulnerability scans do not send the project dependency inventory to OSV.
- Show vulnerable dependency paths, grouped component advisories, reachability signals, upgrade guidance, and no-patch/manual-remediation packages.
- Detect version conflicts, diamond dependencies, license-policy issues, deprecation/yanked releases, stale/abandoned components, bus-factor concerns, and missing security-policy metadata.
- Export terminal, JSON, CSV, HTML, and dependency-free PDF reports.
- Generate CycloneDX or SPDX SBOMs without running the project or its package manager.
- Run a localhost-only live dashboard with graph, shared-risk, and remediation views.
- Enforce CI policy with severity and project-risk exit thresholds.

## Install

### Recommended: install the CLI with pipx

`pipx` installs command-line applications in their own isolated Python environments, avoiding conflicts with system or project packages.

Fedora:

```bash
sudo dnf install pipx
pipx ensurepath
```

If `pipx` is unavailable through your package manager:

```bash
python3 -m pip install --user pipx
python3 -m pipx ensurepath
```

Open a new terminal after `ensurepath`, then install directly from GitHub:

```bash
pipx install "git+https://github.com/OWNER/REPOSITORY.git"
sbom-risk --help
```

Update or remove it later with:

```bash
pipx upgrade sbom-risk-analyzer
pipx uninstall sbom-risk-analyzer
```

### Development installation

```bash
git clone <repository-url>
cd sbom-risk-analyzer
python -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e .
```

The editable installation is for contributors: source-code changes take effect without reinstalling. It is best kept inside the `.venv` rather than installed into the system Python environment.

Windows PowerShell activation for the development environment is:

```powershell
.\.venv\Scripts\Activate.ps1
```

For development and tests:

```bash
python -m pip install -e . pytest
python -m pytest -q
```

## Quick start

```bash
# Scan a project
sbom-risk /path/to/project

# Scan without registry network lookups
sbom-risk /path/to/project --no-registry-metadata

# Fetch npm/PyPI deprecation metadata once, then reuse it locally
sbom-risk sync-registry /path/to/project

# Scan several projects and print an aggregate terminal summary
sbom-risk service-a service-b --no-registry-metadata

# Export an HTML report
sbom-risk /path/to/project --format html --output report.html

# Show all commands and options
sbom-risk --help
sbom-risk sync-osv --help
```

## Supported inputs and ecosystems

| Ecosystem | Inputs |
| --- | --- |
| npm / Node.js | `package-lock.json`, `npm-shrinkwrap.json`, `package.json`, `yarn.lock` |
| Python / PyPI | `requirements.txt`, `poetry.lock`, `pyproject.toml`, `Pipfile.lock` |
| Maven / Java | `pom.xml` |
| Go | `go.mod` |
| Rust / crates.io | `Cargo.lock` |
| Ruby / RubyGems | `Gemfile.lock`, `Gemfile` |
| PHP / Composer | `composer.lock`, `composer.json` |
| SBOMs | `*.cdx.json`, `*.cyclonedx.json`, `*.spdx.json` |

When a resolved lockfile and a source manifest coexist, the resolved lockfile is preferred where applicable. npm graph resolution follows Node's nearest-`node_modules` lookup and does not treat a hoisted transitive dependency as direct merely because it is installed at the root.

Native parsers and local OSV sync currently cover npm, PyPI, Maven, Go, crates.io, RubyGems, and Composer/Packagist. NuGet and other ecosystems are not yet natively parsed.

## Local OSV vulnerability database

OSV archive syncing is explicit. It downloads public advisory archives into a local SQLite database; ordinary scans then read the local database only.

```bash
# Recommended: sync only the ecosystems you use
sbom-risk sync-osv --ecosystem npm --ecosystem PyPI

# Check the cache location, timestamp, and synced ecosystems
sbom-risk sync-osv --status

# Use a custom cache location
sbom-risk sync-osv --osv-db /secure/path/osv.sqlite3 --ecosystem npm

# Scan with that cache
sbom-risk . --osv-db /secure/path/osv.sqlite3
```

The default cache path is `~/.cache/sbom-risk/osv.sqlite3`. A scan warns when that cache is at least seven days old or lacks a usable sync timestamp. Refresh it regularly:

```bash
sbom-risk sync-osv --ecosystem npm --ecosystem PyPI
```

`--online` is available as an opt-in fallback/augmentation, but it submits package names and versions to the OSV API:

```bash
sbom-risk . --online
```

You can also provide a small organization-managed vulnerability file:

```bash
sbom-risk . --vuln-db company-vulnerabilities.json
```

```json
[
  {
    "id": "CVE-2026-0001",
    "ecosystem": "pypi",
    "package": "example",
    "affected": "<2.0.0",
    "severity": "high",
    "summary": "Short advisory summary.",
    "fixed_version": "2.0.0",
    "references": ["https://example.invalid/advisory"]
  }
]
```

## Privacy and network behavior

### Choose the right scan mode

Sending package names and versions to the OSV API is a normal vulnerability-scanning workflow and is often acceptable for public open-source projects. However, it can reveal your technology stack, exact dependency versions, scan timing, and source IP address. That metadata may be sensitive for private products, regulated environments, pre-release software, or internal infrastructure.

| Situation | Recommended command | What leaves the machine |
| --- | --- | --- |
| Public project; latest OSV results are more important than inventory privacy | `sbom-risk . --online` | Package names and versions are sent to OSV. |
| Private project; local advisory matching is preferred | `sbom-risk sync-osv --ecosystem npm --ecosystem PyPI`, then `sbom-risk . --no-registry-metadata` | Nothing during the scan. The explicit sync only downloads public OSV archive data. |
| Private project; deprecation/yanked-release data is acceptable | `sbom-risk sync-registry .`, then `sbom-risk .` | Package names and versions are sent to npm/PyPI during the explicit sync, not during ordinary scans. |

Use `--online` only when you accept the OSV API disclosure. The local-cache workflow is the recommended default for sensitive projects.

| Operation | Network behavior |
| --- | --- |
| `sync-osv` | Downloads public OSV archive data only; no project inventory is uploaded. |
| Normal scan | Uses local OSV and registry metadata caches. It makes no registry request by default. |
| `sync-registry` | Explicitly fetches npm/PyPI deprecation or yanked-release metadata for a project's exact dependencies. |
| `--registry-metadata` | Performs a live npm/PyPI refresh during this scan and updates the local cache. |
| `--no-registry-metadata` | Explicitly disables live registry refresh (the default); cached metadata is still used. |
| `--online` | Sends package names and versions to the OSV API. |
| Dashboard | Binds to `127.0.0.1` only; it does not publish project data to a remote service. |

For the most private local scan after an OSV sync:

```bash
sbom-risk . --no-registry-metadata
```

Sync registry metadata explicitly when you need fresh deprecation/yank signals:

```bash
sbom-risk sync-registry /path/to/project
sbom-risk sync-registry --status
```

Registry fetches are concurrent and identify npm deprecations and PyPI yanked releases. They do not run package-manager commands. Ordinary scans reuse the resulting local cache.

## SBOM generation

Generate an SBOM from supported manifests and lockfiles, then scan it:

```bash
sbom-risk . --generate-sbom cyclonedx
sbom-risk . --generate-sbom spdx --sbom-output /tmp/project.spdx.json
```

Generation is dependency-free: it reads local inputs and does not install dependencies, execute builds, or invoke package managers. If a supported SBOM is already present, it is reused. Generated default files are `sbom.cdx.json` and `sbom.spdx.json`.

* **Lockfile Redirection**: If explicitly pointed to a bare manifest file (e.g., `package.json`), the tool automatically checks for and parses a corresponding lockfile next to it (e.g., `package-lock.json` or `yarn.lock`) to ensure the full transitive dependency graph is recorded.
* **Metadata Component Rooting**: Generated CycloneDX SBOMs include a `metadata.component` entry with `bom-ref: "ROOT"`, ensuring that the dependency graph roots correctly and is fully compliant with standard SBOM readers and validators.

## Findings and remediation

The terminal report groups advisories by component rather than repeating a package for every advisory. Each vulnerable-component section includes:

- advisory count and unique advisory IDs;
- highest severity and CVSS score;
- installed/affected version and highest recommended fixed version;
- a root-to-component dependency path;
- reachability signal; and
- manual-remediation status when no patch is available.

Dependency paths reveal the relationship that introduced a vulnerable package, for example:

```text
ROOT
   └─ express-jwt@1.0.0
      └─ jsonwebtoken@0.4.0
         ├─ 4 advisories; highest CRITICAL
         ├─ Reachability: Unknown
         └─ Fix: upgrade to 9.0.0
```

Version conflicts are grouped per component with all detected versions shown once. Packages with no fixed version appear in a dedicated `⚠ Packages requiring manual remediation` section and are prioritized ahead of equally scored patched packages.

### Reachability and VEX

Reachability is a source-text heuristic based on import/reference signals; it is not AST, call-graph, or runtime reachability analysis. It is intentionally a modest score modifier, not proof that a vulnerability is exploitable or unreachable.

Use VEX overrides for reviewed exceptions:

```bash
sbom-risk . --vex vex.json
```

```json
{
  "CVE-2026-0001": {
    "status": "not_affected",
    "justification": "vulnerable_code_not_present"
  }
}
```

Supported suppression statuses are `not_affected`, `suppressed`, and `approved-exception`.

### Maintenance and health metadata

Lockfiles do not normally include release dates or maintainer information. Supply organization-maintained metadata to enrich maintenance analysis:

```json
{
  "pypi:example": {
    "last_release": "2023-01-10",
    "maintainers_count": 1,
    "has_security_policy": false
  }
}
```

```bash
sbom-risk . --metadata releases.json
```

Signals include stale (1+ year), abandoned (2+ years), single-maintainer bus factor, missing security policy, and registry deprecation/yanking.

### License policy

Provide an allow-list to enforce a strict SPDX policy:

```bash
sbom-risk . --allow-license MIT --allow-license Apache-2.0
```

Without a strict allow-list, missing license metadata in a lockfile is treated as an inventory-enrichment gap rather than a release-blocking conflict. Explicit unknown license declarations, incompatible policy licenses, and relevant copyleft obligations are still reported. License interpretation is a technical signal, not legal advice.

## Threat scoring

The overall score is `0–100` and is not an average of every dependency. Safe dependencies therefore cannot dilute critical risks.

- Each component uses its highest active advisory as its vulnerability contribution; duplicate advisory IDs are deduplicated.
- The highest-risk packages receive decreasing aggregate weights, followed by a saturating curve so several critical packages materially increase project risk without exceeding 100.
- Direct dependencies receive a `1.2×` exposure factor, ordinary transitives `1.0×`, and deep transitives `0.9×`.
- Business criticality (`--criticality 1..5`) is applied after aggregation (`0.8×` through `1.3×`).
- Maintenance, license, and dependency-conflict signals contribute separately.
- Reachability is a modest confidence modifier: reachable `1.15×`, unknown `1.0×`, vulnerable function not used `0.85×`, unreachable `0.75×`.

Reports include attributed contributors and a final classification:

```text
Overall Threat Score: 95.3/100 — CRITICAL
```

Version handling uses PEP 440 comparisons for PyPI and SemVer-style prerelease/build ordering for other common package versions. Unusual ecosystem-specific version schemes can still require manual review.

## Reports and exports

```bash
sbom-risk . --format json --output report.json
sbom-risk . --format csv --output remediation.csv
sbom-risk . --format html --output report.html
sbom-risk . --format pdf --output report.pdf
```

- **Terminal**: grouped remediation-oriented findings and dependency paths.
- **JSON**: components, graph edges, raw findings, score breakdown, and warnings.
- **CSV**: component remediation queue with deduplicated finding IDs.
- **HTML/PDF**: portable renderings of the terminal report.

## Local dashboard

```bash
sbom-risk service-a service-b --serve
sbom-risk . --no-registry-metadata --serve --no-browser
```

The dashboard starts on `http://127.0.0.1:8765` by default and refreshes every 5 seconds. If that port is busy, it automatically selects the next available port. Use `--port` to control it.

It provides:

- **Interactive Dependency Graph**: Render the full transitive dependency tree with zoom/pan and node inspection. Click any component (or search it using `/`) to display its exact dependency paths from `ROOT`. Large projects highlight risky paths while keeping transitive subtrees traversable.
- **Actionable Remediation Playbook**: A queue sorted by risk and patch availability, showing the exact dependency paths of every vulnerable component so you know which package introduced it.
- **Shared Risks & Cluster Analysis**: Cross-project correlations showing components shared across systems, alongside repeated category risk patterns.
- **Real-Time Scanning**: Automatically rescans the workspace for change detection.

## CI and automation

```bash
# Fail when a high-or-higher active finding exists
sbom-risk . --fail-on-severity high --no-registry-metadata

# Fail when the project score exceeds the policy threshold
sbom-risk . --max-risk 40 --format json --output report.json
```

Exit status:

| Code | Meaning |
| --- | --- |
| `0` | Scan completed and configured policy thresholds passed. |
| `1` | Scan completed but a configured severity or risk threshold failed. |
| `2` | Scan, input, or export error. |

The repository includes a GitHub Actions workflow that tests Python 3.10–3.13 on pushes and pull requests.

## Architecture

| Module | Responsibility |
| --- | --- |
| `discovery.py` | Finds supported manifests and SBOMs. |
| `parsers.py` | Isolated manifest and SBOM parsers. |
| `analyzer.py` | NetworkX graph construction, vulnerability matching, policy checks, and scoring. |
| `osv.py` | Public OSV archive synchronization and local SQLite lookup. |
| `sbom.py` | CycloneDX/SPDX generation from supported local inputs. |
| `reporting.py` | Terminal, JSON, CSV, HTML, and PDF reports. |
| `dashboard.py` | Local live dashboard and cross-project correlation. |
| `cli.py` | Command-line interface and CI exit behavior. |

## Contributing and security

See [CONTRIBUTING.md](CONTRIBUTING.md) for local development guidance and [SECURITY.md](SECURITY.md) for private vulnerability reporting. A project license has not been selected yet; choose one before distributing the repository publicly.
