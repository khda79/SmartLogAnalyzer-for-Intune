@echo off
:: ============================================================
:: SmartLogAnalyzer for Intune — Compilation avec Nuitka
:: Nuitka compile en C puis en binaire natif = protection
:: renforcée du code source (difficile à décompiler).
:: ============================================================
:: Prérequis :
::   pip install nuitka ordered-set zstandard
::   Un compilateur C est nécessaire (MSVC ou MinGW)
::   Installation MSVC : https://visualstudio.microsoft.com/
:: ============================================================

echo.
echo ====================================================
echo   SmartLogAnalyzer — Build Nuitka (code protege)
echo ====================================================
echo.

python --version >nul 2>&1
if errorlevel 1 (
    echo [ERREUR] Python introuvable dans le PATH.
    pause
    exit /b 1
)

pip show nuitka >nul 2>&1
if errorlevel 1 (
    echo [INFO] Installation de Nuitka...
    pip install nuitka ordered-set zstandard
)

if exist dist_nuitka rmdir /s /q dist_nuitka

echo [BUILD] Compilation Nuitka en cours (peut prendre 3-10 min)...
echo.

python -m nuitka ^
  --standalone ^
  --onefile ^
  --windows-disable-console ^
  --output-dir=dist_nuitka ^
  --output-filename=SmartLogAnalyzer.exe ^
  --include-package=modules ^
  --include-package=tkinter ^
  --enable-plugin=tk-inter ^
  SmartLogAnalyzer.py

echo.
if exist dist_nuitka\SmartLogAnalyzer.exe (
    echo ====================================================
    echo   [OK] Compilation Nuitka reussie !
    echo   Executable : dist_nuitka\SmartLogAnalyzer.exe
    echo   Code source compile en binaire natif.
    echo ====================================================
) else (
    echo ====================================================
    echo   [ERREUR] La compilation Nuitka a echoue.
    echo ====================================================
)

echo.
pause
