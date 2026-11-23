@echo off
chcp 65001 >nul
cd /d "%~dp0"
set PYTHONUTF8=1
set PYTHONIOENCODING=utf-8
where python >nul 2>&1
if %errorlevel%==0 (set PY=python) else (set PY=py -3)
if not exist experiments\run_test_pipeline.py (
  echo [1/2] Extracting package zip into experiments\ ...
  powershell -NoProfile -Command "Expand-Archive -Force 'qguarder_revision_package_2026-10-18.zip' '_pkg_tmp'"
  robocopy _pkg_tmp\qguarder_revision_package\experiments experiments /E /NFL /NDL /NJH /NJS /NP >nul
  rmdir /s /q _pkg_tmp
)
echo [2/2] Test pipeline: collect - VT lookup (about 2h10m) - evaluate.  Log: experiments\data\revision\test_pipeline.log
%PY% experiments\run_test_pipeline.py %*
echo.
echo Done. You can close this window.
pause
