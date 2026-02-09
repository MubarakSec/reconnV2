# AGENTS.md

Purpose
- Provide a decision-complete roadmap for adding missing stages and upgrading weak stages in ReconnV2.
- Keep changes aligned with the signal bus (signals in results.jsonl) and cross-stage cooperation.

Current Pipeline Notes
- Signals are emitted by WAF, verification, auth discovery, JS intel, and API recon stages.
- Scoring and fuzzing already consume signals for prioritization.
- Scanner stage uses API signals to prioritize API hosts.

**Priority Roadmap (Critical → Least)**
1. GraphQL stage (introspection, schema extraction, basic query tests)
2. Virtual host discovery (Host header fuzzing)
3. Subdomain permutations (dnsgen/alterx style expansion)
4. Cloud asset discovery (S3/GCS/Azure bucket checks)
5. Certificate transparency + ASN pivot (passive expansion)
6. General HTML form parameter mining (beyond auth forms)
7. CMS-specific stages beyond WordPress (Drupal/Joomla)
8. Exploit-level validation (beyond HTTP verification)

**Stage Additions (Spec)**
GraphQL Stage
- Name: `graphql_recon`
- Inputs: URLs from results.jsonl, signals `api_surface`, JS-discovered endpoints.
- Actions:
  1. Detect GraphQL endpoints via POST introspection query.
  2. If allowed, store schema artifact `graphql_schema.json` per host.
  3. Emit signals `graphql_detected`, `graphql_introspection_enabled`.
- Outputs:
  - `type: api` record for GraphQL endpoints.
  - `type: signal` records.
- Runtime config keys:
  - `enable_graphql_recon`, `graphql_max_urls`, `graphql_timeout`, `graphql_rps`, `graphql_per_host_rps`.

Virtual Host Discovery Stage
- Name: `vhost_discovery`
- Inputs: Live HTTP hosts (status 200/301/302/403), optional wordlist.
- Actions:
  1. Send Host header fuzzing against base IP/host.
  2. Detect differences by status, length, title hash.
  3. Emit signals `vhost_found` for candidate hostnames.
- Outputs:
  - `type: hostname` and `type: url` records for discovered vhosts.
- Runtime config keys:
  - `enable_vhost`, `vhost_wordlist`, `vhost_max_hosts`, `vhost_timeout`, `vhost_rps`.

Subdomain Permutations Stage
- Name: `subdomain_permute`
- Inputs: Existing subdomains from passive stage.
- Actions:
  1. Generate permutations (dnsgen/alterx-like rules).
  2. Resolve candidates and add live ones.
- Outputs:
  - `type: hostname` records for new subs.
- Runtime config keys:
  - `enable_subdomain_permute`, `permute_max`, `permute_timeout`.

Cloud Asset Discovery Stage
- Name: `cloud_asset_discovery`
- Inputs: Hostnames, org names, keywords.
- Actions:
  1. Build bucket/container names.
  2. Check public exposure (S3/GCS/Azure).
- Outputs:
  - `type: finding` for public assets.
- Runtime config keys:
  - `enable_cloud_discovery`, `cloud_max_checks`, `cloud_timeout`.

CT + ASN Pivot Stage
- Name: `ct_asn_pivot`
- Inputs: Domains, ASN data from enrichment.
- Actions:
  1. Query certificate transparency logs.
  2. Pivot from ASN to IP/hosts.
- Outputs:
  - `type: hostname` and `type: asset` records.

General HTML Form Parameter Mining Stage
- Name: `html_form_mining`
- Inputs: Live URLs, HTML pages.
- Actions:
  1. Extract all form inputs (not just auth forms).
  2. Emit `parameter` records with examples.

CMS Stages (Drupal/Joomla)
- Add detection tags from httpx tech and URL patterns.
- Run cms-specific scanners when detected.

Exploit-Level Validation
- Extend verification to execute proof-of-concept steps for high-risk findings (careful, opt-in).

**Stage Upgrades (Existing, Not Strong Enough)**
- WAF stage: improve fingerprinting and bypass heuristics.
- API recon: add schema validation, auth-aware probing, GraphQL introspection.
- JS intel: classify endpoints (auth/admin/PII), prioritize sensitive routes.
- Fuzzing: adapt wordlists from API schema and discovered params.
- Vuln scan: add verification chaining and reduce false positives.
- Screenshots: add login/portal detection and basic OCR (optional).

**Cross-Stage Integration Rules**
- Emit signals for all meaningful discoveries.
- Use `context.signal_index()` in later stages for prioritization.
- Add `evidence_id` linking findings to the signal when possible.

**Acceptance Criteria For Each New Stage**
- Has a dedicated runtime config toggle and limits.
- Emits at least one signal type.
- Adds artifacts under `artifacts/` when applicable.
- Updates job stats metadata.
- Respects rate limits and URL allowlist.

**Test Checklist**
- `python -m py_compile` for modified modules.
- Run a small local scan to confirm stage ordering and signal flow.
- Validate that `results.jsonl` contains `type: signal` entries for new stages.
