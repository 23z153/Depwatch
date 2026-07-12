from __future__ import annotations

import argparse
import sys

from .analyzer import analyze
from .reporting import export, global_report, terminal_report
from .dashboard import serve
from .sbom import ensure_sbom
from .osv import DEFAULT_DB, DEFAULT_ECOSYSTEMS, info as osv_info, sync_osv

SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv and argv[0] == "sync-osv":
        return _sync_osv_main(argv[1:])
    parser = argparse.ArgumentParser(
        prog="sbom-risk",
        usage="%(prog)s [OPTIONS] PROJECT [PROJECT ...]\n       %(prog)s sync-osv [SYNC OPTIONS]",
        description="Analyze project dependencies and CycloneDX/SPDX SBOMs.",
        epilog="Local OSV cache: sbom-risk sync-osv --ecosystem npm --ecosystem PyPI\n"
               "Offline scan: sbom-risk PROJECT --no-registry-metadata",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("projects", nargs="+", help="Project directories, manifests, or SBOM files")
    parser.add_argument("--criticality", type=int, default=3, choices=range(1, 6), metavar="1..5", help="Business criticality (default: 3)")
    parser.add_argument("--vuln-db", help="Path to vulnerability database JSON (array of records)")
    parser.add_argument("--metadata", help="Component release metadata JSON for maintenance checks")
    parser.add_argument("--allow-license", action="append", default=None, help="Allowed SPDX license; repeat to define a strict policy")
    parser.add_argument("--project-type", choices=["proprietary-distributed", "proprietary-internal", "open-source"], default="proprietary-distributed", help="Project type context for copyleft license analysis")
    parser.add_argument("--vex", help="Path to VEX overrides JSON file")
    parser.add_argument("--osv-db", default=str(DEFAULT_DB), help="Local OSV SQLite cache (default: ~/.cache/sbom-risk/osv.sqlite3)")
    parser.add_argument("--online", action="store_true", help="Query OSV directly (sends package names and versions; local cache is preferred)")
    registry_group = parser.add_mutually_exclusive_group()
    registry_group.add_argument("--registry-metadata", dest="registry_metadata", action="store_true", default=True, help="Query npm and PyPI for deprecated or yanked versions (default)")
    registry_group.add_argument("--no-registry-metadata", dest="registry_metadata", action="store_false", help="Skip registry checks; useful for offline/private scans")
    parser.add_argument("--generate-sbom", choices=["cyclonedx", "spdx"], help="Generate an SBOM when none exists, then analyze it")
    parser.add_argument("--sbom-output", help="Where to write a generated SBOM (one project only)")
    parser.add_argument("--fail-on-severity", choices=SEVERITY_RANK, help="Exit with status 1 when a finding meets this severity (for CI)")
    parser.add_argument("--max-risk", type=float, help="Exit with status 1 when the project risk score exceeds this value (for CI)")
    parser.add_argument("--serve", action="store_true", help="Run the local live risk dashboard")
    parser.add_argument("--port", type=int, default=8765, help="Preferred local dashboard port; next free port is used if occupied (default: 8765)")
    parser.add_argument("--refresh-seconds", type=int, default=10, help="Dashboard rescan interval in seconds (default: 10)")
    parser.add_argument("--no-browser", action="store_true", help="Do not open the dashboard in the default browser")
    parser.add_argument("--format", choices=["terminal", "json", "csv", "html", "pdf"], default="terminal")
    parser.add_argument("--output", "-o", help="Export destination (required for non-terminal formats)")
    parser.add_argument("--no-tree", action="store_true", help="Hide dependency tree in terminal output")
    if not argv:
        parser.print_help()
        return 0
    args = parser.parse_args(argv)
    if args.format != "terminal" and not args.output: parser.error("--output is required when --format is not terminal")
    if len(args.projects) > 1 and args.format != "terminal": parser.error("Export one project at a time; run separate commands to avoid overwriting output")
    if args.sbom_output and not args.generate_sbom: parser.error("--sbom-output requires --generate-sbom")
    if args.sbom_output and len(args.projects) > 1: parser.error("--sbom-output supports one project at a time")
    options = {"criticality": args.criticality, "vulnerability_db": args.vuln_db, "metadata_file": args.metadata,
               "allowed_licenses": set(args.allow_license) if args.allow_license else None, "project_type": args.project_type,
               "vex_file": args.vex, "online": args.online, "registry_metadata_online": args.registry_metadata,
               "osv_db": args.osv_db}
    scan_projects = args.projects
    if args.generate_sbom:
        scan_projects = []
        for project in args.projects:
            try:
                print(f"Preparing {args.generate_sbom.upper()} SBOM for: {project}")
                sbom, generated = ensure_sbom(project, args.generate_sbom, args.sbom_output)
                print(f"{'Generated' if generated else 'Using existing'} SBOM: {sbom}")
                scan_projects.append(str(sbom))
            except (OSError, ValueError) as exc:
                print(f"error: {project}: {exc}", file=sys.stderr)
                return 2
    if args.serve:
        serve(scan_projects, options, args.port, args.refresh_seconds, open_browser=not args.no_browser)
        return 0
    status = 0
    results = []
    for project in scan_projects:
        try:
            result = analyze(project, **options)
            results.append(result)
            if args.format == "terminal": print(terminal_report(result, not args.no_tree))
            else: export(result, args.format, args.output); print(f"Wrote {args.format.upper()} report: {args.output}")
            if _fails_threshold(result, args.fail_on_severity, args.max_risk):
                status = max(status, 1)
        except (OSError, ValueError) as exc:
            print(f"error: {project}: {exc}", file=sys.stderr); status = 2
    if len(results) > 1 and args.format == "terminal":
        print(global_report(results))
    return status


def _fails_threshold(result, severity: str | None, max_risk: float | None) -> bool:
    if max_risk is not None and result.overall_score > max_risk:
        return True
    if severity is None:
        return False
    threshold = SEVERITY_RANK[severity]
    findings = result.vulnerabilities + result.license_conflicts + result.unmaintained + result.version_conflicts
    return any(SEVERITY_RANK.get(f.severity, 0) >= threshold for f in findings)


def _sync_osv_main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(prog="sbom-risk sync-osv", description="Download public OSV archives into a local cache. No project data is uploaded.")
    parser.add_argument("--osv-db", default=str(DEFAULT_DB), help="Local SQLite destination")
    parser.add_argument("--ecosystem", action="append", choices=DEFAULT_ECOSYSTEMS, help="OSV ecosystem to cache; repeatable (defaults to common ecosystems)")
    parser.add_argument("--timeout", type=int, default=120, help="Per-download timeout in seconds")
    parser.add_argument("--status", action="store_true", help="Show cache metadata without syncing")
    args = parser.parse_args(argv)
    if args.status:
        metadata = osv_info(args.osv_db)
        print(f"OSV cache: {args.osv_db}\n" + ("\n".join(f"{k}: {v}" for k, v in metadata.items()) if metadata else "not yet synced"))
        return 0
    try:
        counts = sync_osv(args.osv_db, args.ecosystem or DEFAULT_ECOSYSTEMS, args.timeout)
    except (OSError, ValueError, __import__("zipfile").BadZipFile) as exc:
        print(f"error: OSV sync failed: {exc}", file=sys.stderr)
        return 2
    print(f"OSV local cache ready: {args.osv_db} ({sum(counts.values()):,} affected-package records)")
    return 0


if __name__ == "__main__": raise SystemExit(main())
