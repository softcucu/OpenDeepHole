@echo off
REM OpenDeepHole Agent - Windows startup script
REM
REM Usage:
REM   run_agent.bat <project_path> [OPTIONS]
REM
REM Examples:
REM   run_agent.bat C:\path\to\source
REM   run_agent.bat C:\path\to\source --server http://192.168.1.10:8000
REM   run_agent.bat C:\path\to\source --checkers npd,oob --name "MyProject"
REM   run_agent.bat C:\path\to\source --dry-run
REM
REM Before first run: edit agent.yaml to set server_url and OpenCode model pool.

cd /d "%~dp0"
set "BUNDLED_CTAGS_DIR=%~dp0ctags-p6.2.20260517.0-x64"
if exist "%BUNDLED_CTAGS_DIR%\ctags.exe" set "PATH=%BUNDLED_CTAGS_DIR%;%PATH%"

set "PYTHON_CMD="

where.exe /q python3 >nul 2>&1
if not errorlevel 1 (
    set "PYTHON_CMD=python3"
    goto :PYTHON_FOUND
)

where.exe /q python >nul 2>&1
if not errorlevel 1 (
    set "PYTHON_CMD=python"
    goto :PYTHON_FOUND
)

echo [ERROR] Python was not found. Install Python 3 or add it to PATH.
pause
exit /b 1

:PYTHON_FOUND
echo [INFO] Using Python command: %PYTHON_CMD%

for /f "delims=" %%I in ('%PYTHON_CMD% -c "import sysconfig; print(sysconfig.get_path('scripts') or '')" 2^>nul') do set "PYTHON_SCRIPTS=%%I"
if defined PYTHON_SCRIPTS set "PATH=%PYTHON_SCRIPTS%;%PATH%"

set "MISSING_DEPS="
%PYTHON_CMD% -c "import semgrep, httpx, websockets, yaml, pydantic, tree_sitter, tree_sitter_cpp, uvicorn, fastapi; from importlib.metadata import version; from mcp.server.fastmcp import FastMCP; assert int(version('sse-starlette').split('.', 1)[0]) >= 3" 2>nul
if errorlevel 1 set "MISSING_DEPS=1"

where semgrep >nul 2>nul
if errorlevel 1 set "MISSING_DEPS=1"

if defined MISSING_DEPS (
    echo Installing agent dependencies...
    %PYTHON_CMD% -m pip install -r requirements-agent.txt || exit /b 1
    for /f "delims=" %%I in ('%PYTHON_CMD% -c "import sysconfig; print(sysconfig.get_path('scripts') or '')" 2^>nul') do set "PYTHON_SCRIPTS=%%I"
    if defined PYTHON_SCRIPTS set "PATH=%PYTHON_SCRIPTS%;%PATH%"
)

where semgrep >nul 2>nul
if errorlevel 1 (
    echo semgrep command not found after installing dependencies.
    exit /b 1
)

call :CHECK_SOURCE_INDEX_TOOLS
if errorlevel 1 exit /b 1

%PYTHON_CMD% -m deephole_client.main %*
exit /b %ERRORLEVEL%

:PRINT_SOURCE_TOOL_HELP
echo Required source indexing tools are missing.
echo The Agent package should include ctags-p6.2.20260517.0-x64\ctags.exe.
echo Download a fresh Agent package or install Universal Ctags manually.
exit /b 0

:CHECK_SOURCE_INDEX_TOOLS
set "SOURCE_TOOL_MISSING="
where ctags >nul 2>nul
if errorlevel 1 set "SOURCE_TOOL_MISSING=1"

if defined SOURCE_TOOL_MISSING (
    call :PRINT_SOURCE_TOOL_HELP
    exit /b 1
)

ctags --version 2>nul | findstr /C:"Universal Ctags" >nul
if errorlevel 1 (
    echo ctags must be Universal Ctags.
    call :PRINT_SOURCE_TOOL_HELP
    exit /b 1
)

call :CTAGS_SUPPORTS_JSON_OUTPUT
if errorlevel 1 (
    echo ctags must support JSON output.
    call :PRINT_SOURCE_TOOL_HELP
    exit /b 1
)
exit /b 0

:CTAGS_SUPPORTS_JSON_OUTPUT
setlocal
set "CTAGS_PROBE_DIR=%TEMP%\opendeephole-ctags-%RANDOM%-%RANDOM%"
mkdir "%CTAGS_PROBE_DIR%" >nul 2>nul
if errorlevel 1 (
    endlocal
    exit /b 1
)
set "CTAGS_PROBE_SOURCE=%CTAGS_PROBE_DIR%\probe.c"
set "CTAGS_PROBE_OUTPUT=%CTAGS_PROBE_DIR%\out.json"
> "%CTAGS_PROBE_SOURCE%" echo int odh_ctags_json_probe(void^) { return 0; }
ctags --output-format=json -o - "%CTAGS_PROBE_SOURCE%" > "%CTAGS_PROBE_OUTPUT%" 2>nul
if errorlevel 1 (
    rd /s /q "%CTAGS_PROBE_DIR%" >nul 2>nul
    endlocal
    exit /b 1
)
findstr /I /C:"_type" "%CTAGS_PROBE_OUTPUT%" >nul
if errorlevel 1 (
    rd /s /q "%CTAGS_PROBE_DIR%" >nul 2>nul
    endlocal
    exit /b 1
)
rd /s /q "%CTAGS_PROBE_DIR%" >nul 2>nul
endlocal
exit /b 0
