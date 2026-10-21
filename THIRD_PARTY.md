# Third-party sources

Dependencies installed from Python packages and Homebrew keep their upstream licenses; package locks identify tested versions. This repository does not vendor their executables or model weights.

- Semgrep: https://github.com/semgrep/semgrep
- mobsfscan and its bundled mobile rules: https://github.com/MobSF/mobsfscan (LGPL-3.0 upstream; rules are installed by the package, not copied here).
- Gitleaks: https://github.com/gitleaks/gitleaks
- OSV-Scanner: https://github.com/google/osv-scanner
- llama.cpp: https://github.com/ggml-org/llama.cpp (MIT upstream; converter checkout stays local and ignored).
- `tests/sarif-schema.json`: OASIS SARIF 2.1.0 schema, obtained from https://github.com/oasis-tcs/sarif-spec/blob/main/sarif-2.1/schema/sarif-schema-2.1.0.json. Preserve upstream schema notices and consult the upstream repository's specification/IPR terms before redistribution.
- Qwen and Cisco Foundation-Sec weights: see `docs/model-provenance.md` for source, revision and license information. They are downloaded separately and never committed. Cisco changes are Apache-2.0; the base remains subject to Meta's Llama 3.1 Community License.
- Rules in `src/mobile_audit/rules.yaml` were authored for this project; report metadata records their provenance and content hash.

The project's original code is MIT-licensed (see [LICENSE](LICENSE)). The MIT grant does not cover the third-party material listed above; `tests/sarif-schema.json` remains under OASIS terms. No upstream license is overridden here.
