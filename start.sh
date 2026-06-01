#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

echo "=== OpenDeepHole 一键构建重启 ==="

# 1. 停止已有进程
echo "[1/3] 停止已有进程..."
pkill -f "uvicorn backend.main:app" 2>/dev/null && echo "  已停止 uvicorn" || echo "  uvicorn 未运行"
sleep 1

# 2. 构建前端
echo "[2/3] 构建前端..."
cd frontend
npm run build
cd "$SCRIPT_DIR"
echo "  前端构建完成"

# 3. 启动后端（前台运行）
echo "[3/3] 启动后端 (port 8000)..."
echo "=== 服务已启动，Ctrl+C 停止 ==="
WS_PING_INTERVAL="${OPENDEEPHOLE_SERVER_WS_PING_INTERVAL:-30}"
WS_PING_TIMEOUT="${OPENDEEPHOLE_SERVER_WS_PING_TIMEOUT:-120}"
python3 -m uvicorn backend.main:app \
  --host 0.0.0.0 \
  --port 8000 \
  --ws-ping-interval "$WS_PING_INTERVAL" \
  --ws-ping-timeout "$WS_PING_TIMEOUT"
