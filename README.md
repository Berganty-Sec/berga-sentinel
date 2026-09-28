# Berga Sentinel

Berga Sentinel is a Python desktop tool for **authorized network inventory and security assessment**, developed by Berga CyberSec. It discovers observable assets, collects service and local Windows configuration evidence, applies contextual risk rules, and creates reports for technical review and client presentation.

> Use the tool only on networks and systems for which you have explicit authorization. The current version is read-only: it does not exploit vulnerabilities or apply changes.

## Features

- Host discovery using ICMP, catalogued TCP ports, and the local neighbor table.
- Asset inventory with IP address, available hostname, observed ports and services, and MAC address/vendor when available.
- Probabilistic classification of computers, mobile devices, printers, and network equipment.
- Unauthenticated protocol checks that provide context about exposed services.
- Local checks for firewall, Microsoft Defender, available updates, and UAC on the auditor's Windows computer.
- Findings with evidence, remediation recommendations, and heuristic prioritization based on confidence and context.
- Technical, operational, and client-friendly HTML/PDF reports, plus CSV inventories and complete JSON data.
- Technical logs and a readable audit summary.
- Bounded host/TCP/ICMP/DNS/ARP/fingerprint concurrency, configurable timeouts, and cooperative cancellation.
- Collection timestamps and per-field provenance in the inventory, plus a local audit history and comparison report.

## Requirements

- Windows 10/11 for the desktop interface and Windows posture checks.
- Python 3.10 or later.
- `reportlab` is installed as a package dependency for PDF export.
- Python 3.10 uses `tomli` for optional TOML configuration; newer versions use the standard library parser.

## Installation and usage

In PowerShell, from the project directory:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -e .
Copy-Item .\berga-sentinel.toml.example .\berga-sentinel.toml
python -m berga_sentinel
```

In the interface, enter the authorized IPv4 CIDR and confirm authorization before starting. Each audit is currently limited to 256 addresses.

The optional `berga-sentinel.toml` is read from the current working directory and is ignored by Git. Without it, validated built-in defaults apply. The example file lists timeouts, host and worker limits, TCP ports, risk thresholds, report formats/profiles, and log level. Unknown configuration keys are rejected.

## Audit output

Each run creates a dedicated directory under `output/<audit-id>/`. All files for that run are kept together:

| File | Contents |
| --- | --- |
| `relatorio-tecnico.html` / `.pdf` | Detailed evidence, diagnostics, and recommendations for technical review |
| `relatorio-operacional.html` / `.pdf` | Inventory, findings, and recommendations for follow-up |
| `relatorio-cliente.html` / `.pdf` | Plain-language summary without raw scanner observations |
| `inventario-detalhado.csv` | Technical inventory |
| `inventario-cliente.csv` | Simplified inventory |
| `auditoria-completa.json` | Complete run data, including raw technical observations; confidential internal artifact |
| `auditoria-<id>-tecnico.log` | Technical execution log |
| `auditoria-<id>-cliente.log` | Readable audit summary |
| `comparacao-anterior.html` | New, resolved, and persistent findings plus inventory changes, when a previous snapshot exists |

Audit files may contain client network addresses and system details. Store and share them according to the confidentiality and retention terms agreed with the client. For client presentation, share only `relatorio-cliente.html` or `relatorio-cliente.pdf` and, if needed, `inventario-cliente.csv`. The complete JSON and technical logs are internal audit artifacts.

Audit snapshots are kept together in `output/history/` (up to 500 records). The technical inventory export includes collection time and per-field provenance. Client reports omit raw scanner notes and technical evidence details.

## Architecture

The workflow is modular: **Scanner → Inventory → Evidence → Rules → Risk → Reporting**.

- `scanner`, `neighbors`, and `service_catalog`: discovery probes and the port catalog.
- `inventory`, `oui`, and `fingerprints`: inventory, local OUI lookup, and probabilistic asset classification.
- `evidence` and `service_fingerprint`: evidence normalization and contextual service checks.
- `checks`: read-only Windows checks on the local auditor computer.
- `rules` and `risk`: evidence interpretation and contextual prioritization.
- `reporting`, `client_log`, and `output_layout`: reports and per-audit artifacts.
- `pipeline` and `ui`: workflow orchestration and desktop interface.
- `config`: validated centralized settings; `rule_engine` and `rules`: independent evidence rule registry; `presentation`: shared client-safe wording; `history` and `comparison`: snapshots and audit comparisons.

Collectors should produce evidence; independent rules interpret that evidence. The application should not perform automatic remediation.

## Windows checks

Firewall, Microsoft Defender, Windows Update, and UAC are checked only on the Windows computer running Sentinel. The current version does not request credentials or query remote Windows configuration. Use an authorized endpoint-management or local collection process for client computers, and validate imported results with the responsible technical contact. An available update is not automatically a vulnerability, and third-party antivirus software may explain a reported Defender state.

## Scope and limitations

- IPv4 only, with an explicit CIDR and a maximum of 256 addresses per audit.
- Only TCP ports in the current catalog are checked; there is no UDP scan, exploitation, brute force, or login attempt against network services.
- Silent devices, filtered ICMP, firewalls, uncatalogued ports, and randomized MAC addresses may limit discovery. The local neighbor table may also contain stale entries.
- Vendor, device type, and operating system are inferences, not guaranteed identifications. The bundled OUI database is partial and queried locally.
- The update count comes from the Windows Update Agent and does not establish severity, age, applicability, or CVE presence.
- An open port demonstrates observed exposure, not an automatic vulnerability. For example, TCP/445 produces an SMBv1 finding only when protocol negotiation confirms support for the legacy protocol.
- Scores and severities are Berga Sentinel heuristics; they are not CVSS ratings and do not replace professional validation.
- Windows configuration checks do not cover remote computers in this version.

## Development and live integration test

Run the offline unit and mocked integration suite from the repository root:

```powershell
python -m unittest discover -s tests -v
```

These tests do not require or access a real network. To audit the installed dependency tree, install the development tools and run `pip-audit`:

```powershell
python -m pip install -e ".[dev]"
pip-audit
```

The integration test performs a real network scan and **must only be run on an explicitly authorized scope**. Set the authorized CIDR and a list of IP addresses that you have confirmed are active. The test checks coverage of the range and probe catalog, compares known active targets with the inventory, and generates reports from the collected data. No target is hard-coded in the repository.

```powershell
$env:BERGA_SENTINEL_AUTHORIZED = "YES"
$env:BERGA_SENTINEL_LIVE_CIDR = "192.0.2.0/24"
$env:BERGA_SENTINEL_EXPECTED_HOSTS = "192.0.2.10,192.0.2.25"
python -m unittest discover -s tests -v
Remove-Item Env:BERGA_SENTINEL_AUTHORIZED
Remove-Item Env:BERGA_SENTINEL_LIVE_CIDR
Remove-Item Env:BERGA_SENTINEL_EXPECTED_HOSTS
```

Without all three environment variables, the live test is skipped and sends no packets. Comparing against known addresses helps identify false negatives, but devices that block all configured probes may remain invisible. The addresses above use the documentation-only range `192.0.2.0/24`; replace them with values from the explicitly authorized client scope before running the test.
