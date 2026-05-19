#!/bin/bash
# OpenDeepHole Agent — Linux/macOS startup script
#
# Usage:
#   ./run_agent.sh <project_path> [OPTIONS]
#
# Examples:
#   ./run_agent.sh /path/to/source
#   ./run_agent.sh /path/to/source --server http://192.168.1.10:8000
#   ./run_agent.sh /path/to/source --checkers npd,oob --name "MyProject"
#   ./run_agent.sh /path/to/source --dry-run
#
# Before first run: edit agent.yaml to set server_url and llm_api.api_key

set -e
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

PYTHON_CMD=python3
PYTHON_SCRIPTS="$("$PYTHON_CMD" -c 'import sysconfig; print(sysconfig.get_path("scripts") or "")' 2>/dev/null || true)"
if [ -n "$PYTHON_SCRIPTS" ]; then
    export PATH="$PYTHON_SCRIPTS:$PATH"
fi

add_default_msys2_paths() {
    case "$(uname -s 2>/dev/null || echo unknown)" in
        MINGW*|MSYS*|CYGWIN*)
            if [ -d /usr/bin ]; then
                export PATH="/usr/bin:$PATH"
            fi
            if [ -d /mingw64/bin ]; then
                export PATH="/mingw64/bin:$PATH"
            fi
            if [ -d /c/msys64/usr/bin ]; then
                export PATH="/c/msys64/usr/bin:$PATH"
            fi
            if [ -d /c/msys64/mingw64/bin ]; then
                export PATH="/c/msys64/mingw64/bin:$PATH"
            fi
            ;;
    esac
}

print_source_tool_install_help() {
    echo "Required source indexing tools are missing." >&2
    case "$(uname -s 2>/dev/null || echo unknown)" in
        MINGW*|MSYS*|CYGWIN*)
            echo "Windows recommended method: install MSYS2 with winget, then use pacman." >&2
            echo "   winget install -i MSYS2.MSYS2" >&2
            echo "   pacman -S --needed --noconfirm mingw-w64-x86_64-ctags cscope" >&2
            echo "If needed, add C:\\msys64\\mingw64\\bin before C:\\msys64\\usr\\bin in PATH." >&2
            ;;
        Darwin)
            echo "Install with Homebrew:" >&2
            echo "   brew install universal-ctags cscope" >&2
            ;;
        Linux*)
            echo "Install Universal Ctags and cscope with your system package manager, for example:" >&2
            echo "   sudo apt-get install universal-ctags cscope" >&2
            echo "   sudo dnf install ctags cscope" >&2
            echo "   sudo pacman -S ctags cscope" >&2
            ;;
        *)
            echo "Install Universal Ctags and cscope, then make ctags and cscope available on PATH." >&2
            ;;
    esac
}

install_msys2_source_tools() {
    case "$(uname -s 2>/dev/null || echo unknown)" in
        MINGW*|MSYS*|CYGWIN*)
            add_default_msys2_paths
            if ! command -v pacman >/dev/null 2>&1; then
                if command -v winget >/dev/null 2>&1; then
                    echo "Installing MSYS2 with winget..." >&2
                    winget install -i MSYS2.MSYS2
                    add_default_msys2_paths
                fi
            fi

            if ! command -v pacman >/dev/null 2>&1; then
                print_source_tool_install_help
                return 1
            fi

            echo "Installing Universal Ctags and cscope with MSYS2 pacman..." >&2
            pacman -S --needed --noconfirm mingw-w64-x86_64-ctags cscope
            add_default_msys2_paths
            ;;
        *)
            print_source_tool_install_help
            return 1
            ;;
    esac
}

check_source_index_tools() {
    if ! command -v ctags >/dev/null 2>&1 || ! command -v cscope >/dev/null 2>&1; then
        install_msys2_source_tools || return 1
    fi

    if ! command -v ctags >/dev/null 2>&1 || ! command -v cscope >/dev/null 2>&1; then
        print_source_tool_install_help
        return 1
    fi

    if ! ctags --version 2>/dev/null | grep -q "Universal Ctags"; then
        install_msys2_source_tools || return 1
        if ! ctags --version 2>/dev/null | grep -q "Universal Ctags"; then
            echo "ctags must be Universal Ctags." >&2
            print_source_tool_install_help
            return 1
        fi
    fi

    if ! ctags --list-output-formats 2>/dev/null | grep -qi "json"; then
        install_msys2_source_tools || return 1
        if ! ctags --list-output-formats 2>/dev/null | grep -qi "json"; then
            echo "ctags must support JSON output. Ensure the MSYS2 mingw64 bin path is before usr/bin in PATH." >&2
            print_source_tool_install_help
            return 1
        fi
    fi
}

add_default_msys2_paths

# Install dependencies if needed (only on first run or after update)
if ! "$PYTHON_CMD" -c "import httpx, websockets, yaml, pydantic, openai, tree_sitter, tree_sitter_cpp, uvicorn, fastapi; from mcp.server.fastmcp import FastMCP" 2>/dev/null || ! command -v semgrep >/dev/null 2>&1; then
    echo "Installing agent dependencies..."
    "$PYTHON_CMD" -m pip install -r requirements-agent.txt
    PYTHON_SCRIPTS="$("$PYTHON_CMD" -c 'import sysconfig; print(sysconfig.get_path("scripts") or "")' 2>/dev/null || true)"
    if [ -n "$PYTHON_SCRIPTS" ]; then
        export PATH="$PYTHON_SCRIPTS:$PATH"
    fi
fi

add_default_msys2_paths

if ! command -v semgrep >/dev/null 2>&1; then
    echo "semgrep command not found after installing dependencies." >&2
    exit 1
fi

check_source_index_tools

"$PYTHON_CMD" -m agent.main "$@"
