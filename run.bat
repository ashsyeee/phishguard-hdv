@echo off
setlocal
title PhishGuard-HDV
cd /d "%~dp0"

set "PY="
call :try "py -3"
if defined PY goto found
call :try "python"
if defined PY goto found
call :try "%LOCALAPPDATA%\Programs\Python\Python314\python.exe"
if defined PY goto found
call :try "%LOCALAPPDATA%\Programs\Python\Python313\python.exe"
if defined PY goto found
call :try "%LOCALAPPDATA%\Programs\Python\Python312\python.exe"
if defined PY goto found

echo.
echo Python was not found on this computer.
echo Install Python 3.12 or newer from https://www.python.org/downloads/
echo and tick "Add python.exe to PATH" during setup, then run this file again.
echo.
pause
exit /b 1

:found
echo Using: %PY%

if not exist ".env" (
    if exist ".env.example" copy ".env.example" ".env" >nul
    echo Created .env from .env.example. Add your API keys to .env, then run this file again.
)

%PY% -c "import streamlit, xgboost, sklearn, pandas, tldextract, dotenv" >nul 2>nul
if errorlevel 1 (
    echo Installing required packages - this can take a few minutes...
    %PY% -m pip install -r requirements.txt
    if errorlevel 1 (
        echo.
        echo Package installation failed. See the messages above.
        pause
        exit /b 1
    )
)

echo.
echo Starting PhishGuard-HDV. Open http://localhost:8501 in your browser.
echo Close this window to stop the app.
echo.
%PY% -m streamlit run app.py
pause
exit /b 0

:try
%~1 -c "import sys" >nul 2>nul
if errorlevel 1 exit /b 1
set "PY=%~1"
exit /b 0
