# mobile-audit

Local, read-only mobile source security auditing for macOS ARM64. Scanners and inference run inside `sandbox-exec` with all networking denied. No cloud endpoint, no source upload, no builds, no application dependency installation, no remediation, no binary analysis.

## Run

```sh
mobile-audit --doctor
mobile-audit --models
mobile-audit /path/to/source-code
mobile-audit /path/to/source-code --quick
mobile-audit /path/to/source-code --deep
mobile-audit /path/to/source-code --offline
mobile-audit /path/to/source-code --no-llm
mobile-audit /path/to/source-code --output ~/SecurityReports
mobile-audit /path/to/source-code --config /absolute/path/settings.yaml
```

Reports are private timestamped directories outside the audited source: HTML, Markdown, findings JSON, SARIF 2.1.0, coverage JSON, metadata, execution log, and a symbol/import index. They contain proprietary evidence: protect the directory. Quoted literal values in report source evidence are conservatively masked (except simple boolean/empty values); verify full literals locally at the cited location. Raw scanner reports and inference prompts are temporary and removed; detected secret-bearing lines are withheld from AI context. Redaction is best effort for unknown credential formats. Review before sharing.

Exit codes: **0** completed without findings; **1** findings present; **2** invalid input/fatal isolation failure; **3** incomplete scanner/model coverage (takes precedence over findings). Intentionally disabled LLMs do not make a deterministic-only audit incomplete. A skipped reviewer or unavailable advisory ecosystem does make a requested AI audit incomplete. Finding count is never proof of exploitability or comprehensive coverage.

## Installation and reproduction

Clone this repository into a directory you control. Install native tools and the isolated Python package during initial setup; no model downloads are automatic. On the original installation, the command is a symlink into the project environment.

```sh
git clone https://github.com/lectops/mobile-audit.git
cd mobile-audit
uv venv --python 3.11 .venv
uv pip sync --python .venv/bin/python requirements.lock
uv pip install --python .venv/bin/python --no-deps --no-build-isolation -e .
brew install gitleaks llama.cpp osv-scanner
mkdir -p ~/.local/bin
# Refuse to overwrite an existing command; no shell files are edited.
ln -s "$PWD/.venv/bin/mobile-audit" ~/.local/bin/mobile-audit
```

Use the tested native versions in [the validation baseline](docs/validation-summary.md) for scanner compatibility; Homebrew versions can change. `requirements.lock` pins Python versions. Model hashes and conversion revisions are recorded separately. Initial installation and deliberate updates require internet; audits never download packages, rules, models, or databases. Python 3.11 avoids scanner compatibility issues with system-default Python 3.15. No system Python packages are changed.

## Configuration and models

Create a private user configuration (never inside a repository you plan to audit):

```sh
mkdir -p ~/.config/mobile-audit
# Skip this copy if you already have a working private configuration.
test -e ~/.config/mobile-audit/config.yaml || cp config/default.yaml ~/.config/mobile-audit/config.yaml
chmod 600 ~/.config/mobile-audit/config.yaml
```

Edit the model paths to point to your existing local GGUF files. The packaged defaults contain no machine-specific paths. Configuration precedence is packaged defaults, `~/.config/mobile-audit/config.yaml`, then an explicitly supplied `--config`. Nested overrides preserve other settings. No configuration is automatically read from the working directory or audit target. Model paths accept `~` and environment variables; relative paths resolve against their configuration file.

Use `--models` to check configured paths. Missing models produce explicit coverage warnings while deterministic scanning continues. No model weights are stored in Git or Git LFS. Paths must refer to local GGUF weights. Primary and reviewer can each be enabled/disabled. The runtime is `llama-completion` from llama.cpp: no listener, no hosted API, Metal offload (`-ngl 99`), sequential processes, 16K context. The validated installation reused a community Qwen3-Coder 30B abliterated Q4_K_S derivative; it is not an untouched official Qwen release. It supports the qwen3moe architecture. There is no silent model substitution. Foundation-Sec uses official Cisco weights converted locally; see [model provenance](docs/model-provenance.md) and [recorded weight hashes](docs/model-weights.json).

Quick, standard and deep currently use the same deterministic current-file scanner coverage. Deep expands AI investigation/review budgets; Git history is not scanned. Quick/standard/deep default primary subsystem budgets: 1/4/12 files, with up to 3 investigation turns and bounded additional source requests per turn. Reviewer budgets: 2/8/24 candidates. Max snippets: 80 lines initially, at most 101 lines per retrieval. Input cap: 24000 characters; output and time limits are configurable. `audit_timeout` defaults to 1800 seconds and caps scanner/inference budgets. `primary.retries` defaults to zero; `reviewer.retries` defaults to one. Both are capped at two retries. Reviewer generation is constrained by a native llama.cpp JSON schema, with concise reasoning inside the structured review. A malformed reviewer response gets a bounded format-correction retry; other candidates continue if it still fails. Reviewer output is capped at 4096 tokens. Repository content is untrusted data. Models have only JSON source retrieval requests; no terminal, write, build, or network capability. Evidence quotes must match actual retrieved code; invalid citations are rejected. Static claims and model disagreements remain visible. Scanners are never removed because of model disagreement.

## Scanners and coverage

- Semgrep CE with project-authored local generic rules, pinned by a report SHA-256. Covers mobile Java/Kotlin/Swift/Objective-C/Dart/JS/TS patterns plus shared source. This is pattern matching, not complete interprocedural analysis. Generic rules have false positives and incomplete semantic coverage.
- mobsfscan bundled mobile rules for Android and iOS. No complete Flutter/React Native-specific coverage is claimed. Rules with no source location are coverage concerns, not fabricated located findings.
- Gitleaks embedded defaults and a trusted local configuration, scanning current snapshot text files with full secret redaction. No repository-provided scanner configuration is honored intentionally. Deep Git history scanning is currently not implemented and is explicitly reported.
- OSV-Scanner uses only cached offline databases, lockfile extraction, no transitive resolution, no call analysis, no build execution. Confirmed lockfile versions do not prove installed/reachable use. Missing ecosystems produce visible failures. npm database was downloaded during setup; other ecosystems require explicit maintenance. Inferred manifest versions are not reported as confirmed.
- CodeQL is optional and absent; no CodeQL extraction or application builds are run.

Text files up to 1 MB are indexed/snapshotted; binary files, symlinks, generated artifacts, caches and vendor directories are excluded. Excluded directories also exclude nested manifests. No compiler-resolved call graph, whole-program authorization proof, dynamic testing or dependency reachability is provided. macOS sandbox-exec is required; other operating systems fail closed. Reports show actual scanner path coverage and AI retrieval ranges. Snapshot/source hashes detect concurrent changes; avoid editing during audits. Indexes are written per report. AI results are conservatively cached only when the entire indexed source file set and hashes, model file identity, configuration, mode and scanner candidate IDs are unchanged. A cross-file change invalidates the cache. Deterministic scanning is repeated in full; this is not incremental whole-program analysis. Disable reuse with `cache_ai: false`.

## Offline security

`--offline` requires macOS sandbox enforcement; normal audits use the same restrictions. A child sandbox denies `network*` including loopback and denies writes to the original repository. Scanners see a filtered external snapshot. Prompts stay in private temporary files. Inference uses local files directly; Ollama and LM Studio servers are unnecessary. If sandbox-exec is absent or blocked, audits stop closed. This mechanism is deprecated by Apple and must be revalidated after OS upgrades. It does not claim a sandbox against a hostile user modifying files concurrently, kernel compromise, or malicious installed scanner binaries. The parent orchestrator has no network code during audits. Doctor version checks use the same network denial.

## Maintenance (explicit online setup only)

Never update during an audit. Update on an empty trusted directory, then rerun the fixture/tests.

```sh
uv pip install --python .venv/bin/python --upgrade semgrep mobsfscan
brew upgrade gitleaks llama.cpp osv-scanner
# Download only the ecosystems represented by trusted lockfiles in this fixture:
osv-scanner scan source --offline --download-offline-databases --no-resolve --no-call-analysis=go,rust fixtures/vulnerable
# Keep the lock portable: exclude editable local file URLs.
uv pip freeze --python .venv/bin/python | sed '/^-e /d' > requirements.lock
.venv/bin/pytest -q
mobile-audit fixtures/vulnerable --offline --no-llm
```

Despite `--offline`, the explicit OSV **download-offline-databases** maintenance option downloads public advisory data. Never use it on proprietary source. Use a trusted synthetic lockfile per required ecosystem to populate the cache. Normal audits pass no download option. Cache age is reported; over seven days is marked stale, and age measures local download time, not upstream completeness.

Edit bundled `src/mobile_audit/rules.yaml` only through a reviewed change; document provenance/license and rerun tests. Each audit records its hash. mobsfscan rule versions follow its locked package. Model updates are manual: verify origin, license, architecture and hash, seek approval before downloads over 1 GB, test locally, then explicitly change the configured path. No automatic fallback or updates.

## Troubleshooting and tests

`--doctor` checks locations/versions; `--models` reports selected files and readiness without loading large models. Missing models do not prevent deterministic scanning. Reduce budgets/output tokens or increase timeout if inference times out. Memory use is bounded primarily by sequential model loading and context; no models run concurrently in a single audit. Concurrent inference is serialized by a per-user lock; scanner stages may still run concurrently. Check `coverage.json` and `execution.log`; a failed tool never means a clean result. If scanner flags change after an update, pin the tested release or adapt the adapter and rerun fixtures.

```sh
.venv/bin/pytest -q
mobile-audit fixtures/vulnerable --offline --no-llm
mobile-audit fixtures/vulnerable --offline --quick
```

The synthetic fixture uses fake credentials and deliberately insecure patterns. Tests cover discovery, path boundaries, evidence, normalization, deduplication, missing models/scanners, mocked inference, reports/SARIF schema, CLI arguments, OS network/write restrictions, and deterministic integration.

## Uninstall

Remove only `~/.local/bin/mobile-audit` after verifying its symlink target is this project, then remove the project directory if desired. Reports remain in `~/SecurityReports`. Remove `~/.config/mobile-audit/config.yaml` only if you no longer need its private model settings. Models originally in LM Studio/Hugging Face caches are not owned by this project and must not be removed. Homebrew scanners may be shared: uninstall them only after checking other uses. No launch agent, shell configuration, firewall rule or Ollama configuration needs reverting.


## Repository hygiene and CI

This repository contains only the auditor, local rules, synthetic fixtures, tests, portable configuration, dependency locks and sanitized documentation. Model weights, Python environments, downloaded converter source, audit reports, caches and machine-specific inventories remain local and are ignored by Git. The fixture credentials are intentionally fake and are narrowly allowlisted by the repository's `.gitleaks.toml`; the auditor's own Gitleaks adapter still detects them when scanning the fixture.

GitHub Actions runs the project's tests against synthetic temporary source on macOS and checks this repository with redacted Gitleaks output. It does not run proprietary audits or download/invoke LLM weights. Actions are pinned to verified upstream commit IDs. Dependency installation happens only during CI setup. Private configuration and real audit artifacts must never be uploaded as workflow artifacts.

The private repository has no open-source license grant. Review third-party notices before redistributing dependencies, model weights, or upstream schema files; see [third-party sources](THIRD_PARTY.md).
