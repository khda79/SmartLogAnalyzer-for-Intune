@echo off
:: ============================================================
:: SmartLogAnalyzer for Intune - Script de compilation
:: Genere un .exe standalone avec PyInstaller
:: ============================================================

:: Se placer dans le dossier du script (indispensable)
cd /d "%~dp0"

echo.
echo ====================================================
echo   SmartLogAnalyzer for Intune - Build Script
echo ====================================================
echo.
echo Dossier de travail : %CD%
echo.

:: Verifier Python
python --version >nul 2>&1
if errorlevel 1 (
    echo [ERREUR] Python n'est pas installe ou n'est pas dans le PATH.
    echo Installez Python 3.10+ depuis https://python.org
    pause
    exit /b 1
)

:: Verifier version Python >= 3.10
python -c "import sys; sys.exit(0 if sys.version_info >= (3,10) else 1)" >nul 2>&1
if errorlevel 1 (
    echo.
    echo [ERREUR] Python 3.10 ou superieur est requis.
    python --version
    echo.
    echo Installez Python 3.10, 3.11 ou 3.12 depuis https://python.org
    echo puis relancez ce script.
    echo.
    pause
    exit /b 1
)

:: Installer / verifier PyInstaller
echo [1/3] Verification de PyInstaller...
python -m PyInstaller --version >nul 2>&1
if errorlevel 1 (
    echo [INFO] Installation de PyInstaller...
    python -m pip install pyinstaller
    if errorlevel 1 (
        echo [ERREUR] Impossible d'installer PyInstaller.
        pause
        exit /b 1
    )
)

:: Nettoyage des builds precedents
echo [2/3] Nettoyage des anciens fichiers de build...
if exist dist   rmdir /s /q dist
if exist build  rmdir /s /q build
if exist SmartLogAnalyzer.spec del /q SmartLogAnalyzer.spec

:: Compilation PyInstaller
echo [3/3] Compilation en cours...
echo.

python -m PyInstaller --onefile --windowed --name "SmartLogAnalyzer" --icon "logo.ico" --add-data "modules;modules" --add-data "logo.ico;." --add-data "logo.png;." --hidden-import "modules.zip_handler" --hidden-import "modules.mdm_parser" --hidden-import "modules.error_detector" --hidden-import "modules.compliance_checker" --hidden-import "modules.report_generator" --hidden-import "modules.wu_parser" --hidden-import "modules.extra_parser" --hidden-import "modules.mdm_diag_parser" --hidden-import "modules.evtx_parser" --hidden-import "modules.device_parser" --hidden-import "modules.hardware_parser" --hidden-import "modules.ai_analyzer" --hidden-import "modules.health_analyzer" --hidden-import "modules.local_collector" --hidden-import "modules.analysis_summary" --hidden-import "modules.insights" --hidden-import "modules.anonymizer" --hidden-import "PIL" --collect-all "PIL" --hidden-import "tkinter" --hidden-import "tkinter.ttk" --hidden-import "tkinter.filedialog" --hidden-import "tkinter.messagebox" --hidden-import "xml.etree.ElementTree" SmartLogAnalyzer.py

echo.
if exist dist\SmartLogAnalyzer.exe (
    echo ====================================================
    echo   [OK] Compilation reussie !
    echo   Executable : dist\SmartLogAnalyzer.exe
    echo ====================================================
    echo.
    echo Le fichier .exe est standalone - aucune installation
    echo Python requise sur la machine cible.
) else (
    echo ====================================================
    echo   [ERREUR] La compilation a echoue.
    echo   Consultez la sortie PyInstaller ci-dessus.
    echo ====================================================
    pause
    exit /b 1
)

echo.
pause
