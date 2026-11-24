# AI FBI

**AI FBI** is a standalone, local-first security utility by **Ali Kouhzardi**. It provides heuristic scanning for suspicious text, prompts, code, files, and folders; a local audit trail; optional desktop process/network/file monitoring; and a user-controlled quarantine. It is not a certified antivirus product.

## Features

- High-contrast dark Cyber Security Command Center with an RTL-aware navigation rail, four-language selector, live-shield controls, and process/path/quarantine KPIs.
- Dedicated Dashboard, Scanner, Threat Logs, Quarantine, and executive About views, with severity-coded rows, a risk meter, animated scan progress, and file/folder drag-and-drop with a browse fallback.
- On-demand scanning for exposed-secret patterns, destructive command patterns, prompt injection/jailbreak/impersonation language, and suspicious file extensions.
- Confidence-weighted, context-aware findings with target, 0–100 risk score, severity, matched rule IDs, confidence, and recommended action. Placeholder/example values and explanatory comments are filtered where possible.
- Developer Safe and Balanced Guard profiles are available in Community; Strict Lockdown, custom literal rules, branded JSON/HTML audit exports, and in-app scheduled folder scans are Pro features.
- Offline Community/Pro state and a local demo toggle. The included checksum activation format is not a cryptographic signature and must not be used as tamper-resistant commercial entitlement enforcement.
- Optional Solana donations are shown in About. The wallet details live in `config/donate.json`; only send assets over Solana because another network can result in permanent loss.
- File quarantine with a JSON manifest, restore, and permanent delete.
- Persistent language selection in `config/settings.json` under the application data directory. English (US), Persian (RTL-aware UI fields), Russian, and Simplified Chinese are included.
- Local JSONL audit log, editable process allowlist, and configured protected folders.
- Optional `psutil` process/network monitoring and `watchdog` folder monitoring on desktop platforms. The optional tray icon is provided by `pystray` and Pillow.
- Android UI built with Kivy for scanning text/files/folders, language selection, audit log, quarantine actions, and About information.

## Run on desktop

Requires Python 3.10 or later and a desktop Python build with Tk support.

```powershell
python -m pip install -r requirements.txt
python main.py
```

Runtime data is kept outside the installation directory to avoid writing into protected install locations:

- Windows: `%LOCALAPPDATA%\AI FBI\`
- macOS: `~/Library/Application Support/AI FBI/`
- Linux: `$XDG_DATA_HOME/AI FBI/` or `~/.local/share/AI FBI/`

Set `AI_FBI_HOME` to use a different data directory. The settings file is `<data directory>/config/settings.json`; audit records are in `logs/audit.jsonl`; quarantine contents and `quarantine_manifest.json` are in `quarantine/`.

## Build

- Windows: run `build_windows.bat` from a Python environment supported by current PyInstaller. It produces `dist\AI FBI.exe`.
- Windows installer: install Inno Setup 6 and run `build_installer.bat` after the executable build. It produces `dist\AI_FBI_Installer.exe` with Start Menu and optional Desktop shortcuts.
- Android: use Linux (or a supported Buildozer environment) with Android SDK/NDK dependencies installed, then run `bash build_android.sh`. The APK is written under `bin/`. Android storage access depends on OS version and user-granted access; app-private files remain available without broad storage permissions.

The Android package needs Kivy and Python-for-Android through Buildozer. Desktop-only dependencies are optional at runtime and their modules are guarded.

## Safe simulation

Run the inert accuracy fixtures and safe simulation:

```powershell
python tests\simulate_threat.py
python -m unittest tests.test_accuracy -v
```

The tests scan inert sample strings (including a destructive command that is never run), exercise profile and license persistence, and use temporary directories for quarantine/report checks. They do not execute sample code or contact a network.

## Scope and limitations

AI FBI is a best-effort heuristic utility, not a replacement for a maintained antivirus, endpoint detection product, OS permissions, backups, or firewall. A rule match is only an indicator and can be a false positive; absence of findings is not a clean bill of health. It does not execute scanned content, provide kernel-level self-protection, inspect model internals, stop all exfiltration, or modify the host firewall. Process `SUSPEND`/`TERMINATE` operations are exposed by the core API and may fail due to OS permissions or process state. The dashboard's strict mode is a monitoring mode, not a system-wide lockdown. Scheduled scans run only while the desktop application is open. The local demo/checksum licensing mechanism is for product workflow demonstration only and does not provide cryptographic license enforcement.

## Metadata

- Product: AI FBI
- Version: 1.0.0
- Developer: Ali Kouhzardi
