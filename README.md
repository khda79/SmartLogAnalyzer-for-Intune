# SmartLogAnalyzer for Intune

Automated diagnostic analysis tool for Intune Device Diagnostics ZIP files and local device scans.  
Python/tkinter GUI — packaged as a standalone `.exe` via PyInstaller.

> Built by [WorkplaceCloudHub](https://workplacecloudhub.com)

---

## Features

- **ZIP Analysis** — open diagnostic archives downloaded directly from the Intune portal (*Devices → Device diagnostics → Download*)
- **Local Device Scan** — collect diagnostics from the current machine without needing a ZIP (run as administrator)
- **DSRegCmd** — AAD join status, PRT, WAM, tenant, TPM, Hello for Business
- **MDM Enrollments** — reads `HKLM\Software\Microsoft\Enrollments` (type, state, UPN)
- **MDM Diagnostics** — runs `MDMDiagnosticsTool.exe` to generate full MDM CAB report
- **IME Logs** — error detection in IntuneManagementExtension logs (SCCM format)
- **Windows Update** — ETL log decoding via `Get-WindowsUpdateLog`, CAB/ETL file analysis
- **Event Logs** — EVTX parsing with error/warning extraction across System, Application, and MDM channels
- **Firewall** — Domain / Private / Public profiles (EN and FR locale support)
- **Hardware** — CPU, RAM, disk, battery, and driver inventory
- **Compliance** — automatic NON_COMPLIANT / COMPLIANT / UNKNOWN status calculation
- **AI Analysis** — optional AI-powered log interpretation (requires API key)
- **HTML Report** — self-contained export with no external dependencies

---

## Requirements

- Windows 10 / 11
- Python 3.10 or higher (not required if using the compiled `.exe`)
- Runtime uses Python standard libraries plus Pillow for the branded header image
- To compile: `pip install -r requirements.txt`

---

## Usage

### Run from source

```bash
python SmartLogAnalyzer.py
```

### Use the compiled executable

Download `SmartLogAnalyzer.exe` from the [Releases](../../releases) page — no Python installation required.

### Analyze an Intune Diagnostics ZIP

1. Download the ZIP from the Intune portal: *Devices → [Device] → Device diagnostics → Download*
2. Open SmartLogAnalyzer and click **Open ZIP**
3. Click **Analyze**
4. Browse the tabs: *Summary*, *Errors*, *Compliance*, *Device Info*, *IME Logs*, *Event Logs*, *Hardware*, *Files*
5. Export the HTML report via **Export HTML Report**

### Analyze a local device

1. Run SmartLogAnalyzer **as administrator**
2. Click **Analyze Local Device**
3. The tool collects registry, MDM state, logs, and hardware info directly from the current machine

---

## AI Configuration

The AI tab supports Claude, OpenAI, and local Ollama. API keys are entered in the app UI.

By default, API keys are not stored. If **Remember API key on this device** is checked, the key is saved locally in:

```text
%USERPROFILE%\.smartloganalyzer_ai.json
```

Leave that option unchecked on shared or admin workstations.

---

## Build

### PyInstaller (recommended)

```bat
build.bat
```

Output: `dist\SmartLogAnalyzer.exe` — fully standalone, no Python required on the target machine.

### Nuitka (optional)

```bat
build_nuitka.bat
```

---

## Tests

Parser tests use the Python standard library test runner:

```bash
python -m unittest discover -s tests
```

---

## Release Signing

GitHub Actions builds the executable on every push and pull request. Signing and release publication run only when pushing a version tag matching `v*.*.*`, for example:

```bash
git tag v2.1.1
git push origin v2.1.1
```

Tagged builds submit the unsigned executable to SignPath using `SIGNPATH_ORG_ID` and `SIGNPATH_API_TOKEN`, download the signed artifact, then publish it to GitHub Releases.

---

## Project Structure

```
SmartLogAnalyzerForIntune/
├── SmartLogAnalyzer.py          # Main application (tkinter GUI)
├── LICENSE                      # MIT license
├── modules/
│   ├── analysis_summary.py      # Shared report / AI summary builders
│   ├── zip_handler.py           # ZIP extraction and file inventory
│   ├── mdm_parser.py            # DSRegCmd, Enrollments, Firewall, results.xml
│   ├── mdm_diag_parser.py       # MDMDiagHTMLReport.html parser
│   ├── error_detector.py        # Log scanning (IME/SCCM + plain text)
│   ├── compliance_checker.py    # Compliance status calculation
│   ├── report_generator.py      # HTML report generation
│   ├── wu_parser.py             # Windows Update log/ETL parser
│   ├── evtx_parser.py           # Windows Event Log (EVTX) parser
│   ├── extra_parser.py          # CAB, certificates, C2R, and extra logs
│   ├── hardware_parser.py       # CPU, RAM, disk, battery, drivers
│   ├── device_parser.py         # Device identity and OS info
│   ├── local_collector.py       # Live data collection from local machine
│   └── ai_analyzer.py           # AI-powered log analysis
├── build.bat                    # PyInstaller build script
├── build_nuitka.bat             # Nuitka build script
├── logo.ico                     # Application icon
├── requirements.txt
└── tests/                       # Parser unit tests
```

---

## Supported ZIP Format

Intune Device Diagnostics archives follow this naming scheme:

```
(N) RegistryKey HKLM_...  export.reg
(N) Command windir_system32_Dsregcmd_exe_status output.log
(N) Command windir_system32_netsh_exe_advfirewall_show_allprofiles output.log
(N) FolderFiles ...
results.xml
```

Both **English and French** locale outputs are supported (netsh, DSRegCmd).

---

## Recognized Error Code Ranges

| Range | Domain |
|-------|--------|
| `0x8018xxxx` | MDM Enrollment |
| `0x87D1xxxx` | Compliance / Applications |
| `0xCAAxxxxx` | AAD / WAM Authentication |
| `0x8007xxxx` | Windows System |

---

## License

MIT License — see [LICENSE](LICENSE) for details.
