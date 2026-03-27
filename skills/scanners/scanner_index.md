# Scanner Skills — Index

> **Phase**: 2 — Static Reconnaissance
> **Directory**: `skills/scanners/`

This index lists all 7 scanner skills that perform static security analysis and output standardized JSON results.

| Skill ID | File | Responsibility |
|----------|------|----------------|
| S-020 | `ast_scanner.md` | Run PHP AST parser to discover all dangerous sink function calls with argument safety classification |
| S-021 | `semgrep_scanner.md` | Run pattern-matching security rules targeting PHP-specific vulnerability patterns using p/php ruleset |
| S-022 | `phpstan_scanner.md` | Run static type analysis focusing on type-safety issues that may lead to vulnerabilities |
| S-023 | `psalm_scanner.md` | Run taint analysis to track data flow from Source→Sink paths for vulnerability detection |
| S-024 | `codeql_scanner.md` | Run CodeQL deep taint tracking analysis for full Source→Sink path discovery (optional) |
| S-025 | `progpilot_scanner.md` | Run Progpilot security scan with custom Source/Sink definitions tailored to detected framework |
| S-026 | `composer_audit_scanner.md` | Run Composer audit to detect known CVEs in project dependencies with CVE cross-referencing |
