# Validation baseline

Validated on Apple Silicon M4 Max with 64 GiB unified memory and macOS network sandboxing.

- Original test suite: 27 tests passed, no failures or skips. Configuration-portability tests are added alongside this baseline.
- Seven-file synthetic fixture covers Android Java/XML, iOS Swift/plist, Dart and TypeScript, with intentionally fake credentials.
- Deterministic audit: 24 candidates; all four scanners completed.
- Quick two-model audit: 26 candidates and two independent reviews; all checks completed.
- Standard two-model audit: 28 candidates, eight independent reviews, two disagreements retained; all checks completed in approximately 100 seconds.
- JSON and SARIF 2.1.0 validated; all source locations verified; private report permissions; fake token absent from reports; all fixture byte hashes unchanged.
- Source-write denial, loopback bind/connect denial against a live listener, missing-isolation fail-closed behavior, model/scanner failures and bounded retry behavior were tested.
- Deep deterministic mode was exercised. The entire deep AI budget was not benchmarked.

Candidate counts are a recorded baseline, not a golden security oracle. Tool, rule or model changes can change counts. No proprietary audit reports or machine inventory are included in this repository. Personal report locations and complete local execution records stay untracked.

Tested tools: Python 3.11.17, Semgrep 1.181.0, mobsfscan 0.4.3, Gitleaks 8.30.1, OSV-Scanner 2.7.0 and llama.cpp 0.7.0. Model details and weight provenance are recorded separately.
