# Project Memory

This file keeps the important working context for SmartLogAnalyzer for Intune.
Update it after meaningful decisions, workflow discoveries, release changes, or
implementation milestones.

## Standing Preference

- Keep important conversation points in this Markdown file.
- Maintain this file going forward whenever project context changes.
- French is the preferred working language with Khaled.

## Project Context

- Repository: `khda79/SmartLogAnalyzer-for-Intune`.
- Main application: `SmartLogAnalyzer.py`.
- The app is a Windows/Tkinter diagnostic analyzer for Intune Device Diagnostics
  ZIP files and local device captures.
- Python baseline is 3.10+.
- Build path is PyInstaller only; Nuitka support was removed.
- The `.spec`, `build/`, `dist/`, caches and local generated artifacts should
  stay ignored unless explicitly requested.

## Security And Privacy

- AI API keys are saved only when the user checks `Remember API key on this device`.
- Saved AI configuration path: `%USERPROFILE%\.smartloganalyzer_ai.json`.
- Default behavior should remain privacy-preserving: do not store API keys unless requested.
- An anonymized ZIP export exists for support sharing.

## Release And Signing

- GitHub Actions builds and tests on pushes and pull requests.
- SignPath signing and GitHub Release publishing happen only on tags matching
  `v*.*.*`.
- A normal push to `main` does not trigger signing.
- SignPath workflow uses:
  - project slug: `smartloganalyzer-intune`
  - signing policy slug: `release-signing`
  - artifact configuration slug: `single-exe`

## Recent Implemented Features

- Local insights engine:
  - Top 5 actions
  - global search
  - device health score
  - unified timeline
  - local root cause hints without external AI
  - WUfB summary
- Export anonymized diagnostic ZIP.
- Parser tests were added for targeted areas.
- README and build/signing docs were refreshed.
- Windows 11 upgrade compatibility indicators were integrated from the
  SmartM365 PowerShell detection script:
  - source registry path:
    `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\TargetVersionUpgradeExperienceIndicators`
  - Python parser: `modules/win11_compat_parser.py`
  - local collector now exports the registry key
  - ZIP handler categorizes it as `reg_win11_upgrade_indicators`
  - Win11 Readiness tab displays blocking/clear target-version indicators
  - Insights and global search surface blocking upgrade indicators
  - tests cover blocking and clear registry exports

## Verification Habits

- Before committing, run:
  - `python -m unittest discover -s tests`
  - `python -m py_compile SmartLogAnalyzer.py modules\*.py` when relevant
  - `git diff --check`
- Keep commits focused and push after successful verification when the user asks
  to keep Git clean or publish the work.
