#!/usr/bin/env bash
set -euo pipefail

echo "=== Amnezia Web Panel Mini — Test & Build ==="
echo ""

# 1. Проверяем что Python доступен
PYTHON="${PYTHON:-python3}"
echo "[1/7] Checking Python..."
$PYTHON --version

# 2. Устанавливаем зависимости (включая тестовые)
echo "[2/7] Installing dependencies..."
$PYTHON -m pip install -q -r requirements.txt

# 3. Запускаем линтер (если ruff доступен)
echo "[3/7] Running linter..."
if command -v ruff &>/dev/null; then
    ruff check app.py managers/ || echo "WARNING: lint issues found"
else
    echo "  ruff not found, skipping lint"
fi

# 4. Запускаем тесты
echo "[4/7] Running tests..."
$PYTHON -m pytest tests/ -v --tb=short 2>&1 || {
    echo "ERROR: Tests failed!"
    exit 1
}

# 5. Проверяем Docker
echo "[5/7] Checking Docker..."
if ! command -v docker &>/dev/null; then
    echo "WARNING: Docker not found, skipping build"
    echo ""
    echo "=== All Python checks passed ==="
    exit 0
fi

# 6. Собираем Docker image (multistage)
echo "[6/7] Building Docker image..."
docker build -t amnezia-panel:test . || {
    echo "ERROR: Docker build failed!"
    exit 1
}

# 7. Проверяем образ
echo "[7/7] Verifying image..."
docker run --rm amnezia-panel:test python3 -c "import app; print('Import OK')" || {
    echo "ERROR: Image verification failed!"
    exit 1
}

echo ""
echo "=== All checks passed ==="
