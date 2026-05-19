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
REM Before first run: edit agent.yaml to set server_url and llm_api.api_key

cd /d "%~dp0"

where python3 >nul 2>nul
if %errorlevel%==0 (
    set "PYTHON_CMD=python3"
) else (
    set "PYTHON_CMD=python"
)

for /f "delims=" %%I in ('%PYTHON_CMD% -c "import sysconfig; print(sysconfig.get_path('scripts') or '')" 2^>nul') do set "PYTHON_SCRIPTS=%%I"
if defined PYTHON_SCRIPTS set "PATH=%PYTHON_SCRIPTS%;%PATH%"

call :ADD_DEFAULT_MSYS2_PATHS

set "MISSING_DEPS="
%PYTHON_CMD% -c "import semgrep, httpx, websockets, yaml, pydantic, openai, tree_sitter, tree_sitter_cpp, uvicorn, fastapi; from mcp.server.fastmcp import FastMCP" 2>nul
if errorlevel 1 set "MISSING_DEPS=1"

where semgrep >nul 2>nul
if errorlevel 1 set "MISSING_DEPS=1"

if defined MISSING_DEPS (
    echo Installing agent dependencies...
    %PYTHON_CMD% -m pip install -r requirements-agent.txt || exit /b 1
    for /f "delims=" %%I in ('%PYTHON_CMD% -c "import sysconfig; print(sysconfig.get_path('scripts') or '')" 2^>nul') do set "PYTHON_SCRIPTS=%%I"
    if defined PYTHON_SCRIPTS set "PATH=%PYTHON_SCRIPTS%;%PATH%"
)

call :ADD_DEFAULT_MSYS2_PATHS

where semgrep >nul 2>nul
if errorlevel 1 (
    echo semgrep command not found after installing dependencies.
    exit /b 1
)

call :CHECK_SOURCE_INDEX_TOOLS
if errorlevel 1 exit /b 1

%PYTHON_CMD% -m agent.main %*
exit /b %ERRORLEVEL%

:ADD_DEFAULT_MSYS2_PATHS
if exist "C:\msys64\usr\bin\bash.exe" set "PATH=C:\msys64\usr\bin;%PATH%"
if exist "C:\msys64\mingw64\bin\ctags.exe" set "PATH=C:\msys64\mingw64\bin;%PATH%"
exit /b 0

:PRINT_MSYS2_SOURCE_TOOL_HELP
echo Required source indexing tools are missing.
echo This script can install MSYS2 automatically when winget is available:
echo    winget install -i MSYS2.MSYS2
echo Then it installs the source indexing tools with MSYS2 pacman:
echo    pacman -S --needed --noconfirm mingw-w64-x86_64-ctags
echo If automatic install fails, install MSYS2 from https://www.msys2.org/
echo and add these directories to PATH, with mingw64 before usr:
echo    C:\msys64\mingw64\bin
echo    C:\msys64\usr\bin
exit /b 0

:INSTALL_MSYS2_SOURCE_TOOLS
call :ADD_DEFAULT_MSYS2_PATHS
if not exist "C:\msys64\usr\bin\bash.exe" (
    where winget >nul 2>nul
    if errorlevel 1 (
        echo winget command not found. Cannot install MSYS2 automatically.
        call :PRINT_MSYS2_SOURCE_TOOL_HELP
        exit /b 1
    )
    echo Installing MSYS2 with winget...
    winget install -i MSYS2.MSYS2 || exit /b 1
    call :ADD_DEFAULT_MSYS2_PATHS
)

if not exist "C:\msys64\usr\bin\bash.exe" (
    echo MSYS2 was not found at C:\msys64 after installation.
    call :PRINT_MSYS2_SOURCE_TOOL_HELP
    exit /b 1
)

echo Installing Universal Ctags with MSYS2 pacman...
"C:\msys64\usr\bin\bash.exe" -lc "pacman -S --needed --noconfirm mingw-w64-x86_64-ctags" || exit /b 1
call :ADD_DEFAULT_MSYS2_PATHS
exit /b 0

:CHECK_SOURCE_INDEX_TOOLS
set "SOURCE_TOOL_MISSING="
where ctags >nul 2>nul
if errorlevel 1 set "SOURCE_TOOL_MISSING=1"

if defined SOURCE_TOOL_MISSING (
    call :INSTALL_MSYS2_SOURCE_TOOLS
    if errorlevel 1 exit /b 1
    set "SOURCE_TOOL_MISSING="
    where ctags >nul 2>nul
    if errorlevel 1 set "SOURCE_TOOL_MISSING=1"
    if defined SOURCE_TOOL_MISSING (
        call :PRINT_MSYS2_SOURCE_TOOL_HELP
        exit /b 1
    )
)

ctags --version 2>nul | findstr /C:"Universal Ctags" >nul
if errorlevel 1 (
    call :INSTALL_MSYS2_SOURCE_TOOLS
    if errorlevel 1 exit /b 1
    ctags --version 2>nul | findstr /C:"Universal Ctags" >nul
    if errorlevel 1 (
        echo ctags must be Universal Ctags.
        call :PRINT_MSYS2_SOURCE_TOOL_HELP
        exit /b 1
    )
)

ctags --list-output-formats 2>nul | findstr /I /C:"json" >nul
if errorlevel 1 (
    call :INSTALL_MSYS2_SOURCE_TOOLS
    if errorlevel 1 exit /b 1
    ctags --list-output-formats 2>nul | findstr /I /C:"json" >nul
    if errorlevel 1 (
        echo ctags must support JSON output. Ensure C:\msys64\mingw64\bin appears before C:\msys64\usr\bin in PATH.
        call :PRINT_MSYS2_SOURCE_TOOL_HELP
        exit /b 1
    )
)
exit /b 0
