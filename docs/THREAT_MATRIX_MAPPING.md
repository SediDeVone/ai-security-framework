# AI Security Framework — Comprehensive Threat Matrix & Defense Mapping

This document provides a complete cross-check of our repository against standard AI security threat models, attack vectors, and defensive controls.

---

## 🗺️ Master Mapping Matrix

| Threat Category / Domain | Key Threat / Vector | Repository Defense / Component |
| :--- | :--- | :--- |
| **Exposure & Metadata** | Image EXIF metadata leaks (GPS, device info) | `scanner/exif_cleaner.py` (Strips EXIF data before LLM processing) |
| **Exposure & Metadata** | Domain typosquatting (`dnstwist`) | Documented in `docs/THREAT_MATRIX_MAPPING.md` |
| **Data Leaks & Injections** | Accidental chat leaks & PII disclosure | Microsoft Presidio PII redaction + Polish PESEL/NIP (`scanner/scanner_service.py`) |
| **Data Leaks & Injections** | ASCII Smuggling (Unicode Tag block U+E0000-U+E007F) | `scanner/unicode_cleaner.py` (Strips invisible tags & zero-width characters) |
| **Data Leaks & Injections** | Slopsquatting (Hallucinated PyPI/npm packages) | `harness/hooks/slopsquatting_guard.py` (Verifies package existence & age on PyPI) |
| **Advanced Agent Attacks** | Memory Poisoning (`CLAUDE.md`, `AGENTS.md`) | `harness/hooks/supply_chain_check.sh` (Adversis Sketchy config audit) |
| **Advanced Agent Attacks** | CaMeL Dual LLM (Privileged vs Quarantined) | `scanner/camel.py` (DeepMind 2025 CaMeL architecture pattern) |
| **Advanced Agent Attacks** | Improper Output Handling (XSS, SSRF via output) | `scanner/output_sanitizer.py` (HTML tag escaping & URL validation) |
| **Detection & Defense** | 6 Pillars of AI Security | `docs/AI_SECURITY_PILLARS.md` & `scanner/scanner_service.py` |
| **Detection & Defense** | Emergency Kill Switch & Status Observability | `/kill-switch` & `/health` endpoints + `make kill-switch` |
| **Detection & Defense** | Pre-deploy Red-Teaming (`promptfoo` / `garak`) | `redteam/promptfoo.yaml` & `make redteam` target |

---

## 🛠️ Detailed Pillar Breakdown

### Part 1: Exposure & Metadata Protection
- **EXIF Stripping**: Images uploaded to multimodal models often leak sensitive metadata (home GPS coordinates, timestamps, camera model). `scanner/exif_cleaner.py` removes EXIF headers automatically.

### Part 2: Supply Chain & Slopsquatting Defense
- **Slopsquatting**: 19.7% of AI-generated code contains hallucinated package names. Attackers register these on PyPI/npm to infect developers (`pip install`). `harness/hooks/slopsquatting_guard.py` checks PyPI API to ensure packages exist and are older than 30 days before `pip install` runs.
- **ASCII Smuggling**: Attackers hide malicious instructions in invisible Unicode Tag bytes (U+E0000-U+E007F) or zero-width spaces. `scanner/unicode_cleaner.py` normalizes all text to NFKC and strips non-printable tags.

### Part 3: Advanced Agent & RAG Security
- **Improper Output Handling (OWASP LLM05)**: LLM outputs containing HTML (`<img onerror=...>`) or unescaped Markdown can cause Stored XSS or RCE when rendered. `scanner/output_sanitizer.py` sanitizes responses before UI rendering.
- **CaMeL Pattern (DeepMind 2025)**: Prevents indirect prompt injection from escalating into tool calls by separating Privileged LLM (control flow) from Quarantined LLM (data flow).

### Part 4: Red-Teaming & Runtime Guardrails
- **Pre-Deploy Red-Teaming**: `redteam/promptfoo.yaml` allows running automated prompt injection probes (`garak`/`promptfoo`) in CI/CD pipelines.
- **Incident Response (IR)**: Emergency `/kill-switch` endpoint allows instantaneous lockdown during an active agent hijacking event.
