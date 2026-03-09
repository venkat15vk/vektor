#!/bin/bash
set -e

echo "=============================================="
echo "  VEKTOR — Setup & Launch"
echo "=============================================="
echo ""

# --------------------------------------------------
# 1. Verify folder structure
# --------------------------------------------------
echo "[1/7] Verifying folder structure..."

REQUIRED_FILES=(
    "backend/generate_data.py"
    "backend/normalize.py"
    "backend/run_models.py"
    "backend/reason.py"
    "backend/api.py"
    "backend/agent.py"
    "backend/requirements.txt"
    "backend/Dockerfile"
    "backend/models/__init__.py"
    "backend/models/m1_dormancy.py"
    "backend/models/m2_peer.py"
    "backend/models/m3_sod.py"
    "backend/models/m4_session.py"
    "backend/models/m5_contractor.py"
    "backend/models/m6_velocity.py"
    "backend/models/m7_delegation.py"
    "backend/models/m8_shadow.py"
    "backend/models/m9_crossplane.py"
    "frontend/app.jsx"
    "docker-compose.yml"
)

MISSING=0
for f in "${REQUIRED_FILES[@]}"; do
    if [ ! -f "$f" ]; then
        echo "  ❌ Missing: $f"
        MISSING=1
    fi
done

if [ "$MISSING" -eq 1 ]; then
    echo ""
    echo "  ERROR: Missing files. Make sure you are running this"
    echo "  script from the vektor/ project root directory."
    echo ""
    echo "  Expected structure:"
    echo "    vektor/"
    echo "    ├── backend/"
    echo "    │   ├── data/          (created by generate_data.py)"
    echo "    │   ├── models/"
    echo "    │   │   ├── __init__.py"
    echo "    │   │   ├── m1_dormancy.py"
    echo "    │   │   ├── m2_peer.py"
    echo "    │   │   ├── m3_sod.py"
    echo "    │   │   ├── m4_session.py"
    echo "    │   │   ├── m5_contractor.py"
    echo "    │   │   ├── m6_velocity.py"
    echo "    │   │   ├── m7_delegation.py"
    echo "    │   │   ├── m8_shadow.py"
    echo "    │   │   └── m9_crossplane.py"
    echo "    │   ├── generate_data.py"
    echo "    │   ├── normalize.py"
    echo "    │   ├── run_models.py"
    echo "    │   ├── reason.py"
    echo "    │   ├── api.py"
    echo "    │   ├── agent.py"
    echo "    │   ├── requirements.txt"
    echo "    │   └── Dockerfile"
    echo "    ├── frontend/"
    echo "    │   └── app.jsx"
    echo "    ├── docker-compose.yml"
    echo "    └── setup.sh"
    exit 1
fi
echo "  ✅ All files present"

# --------------------------------------------------
# 2. Create virtual environment & install deps
# --------------------------------------------------
echo ""
echo "[2/7] Installing Python dependencies..."

cd backend

if [ ! -d ".venv" ]; then
    python3 -m venv .venv
fi
source .venv/bin/activate

pip install --upgrade pip -q
pip install -r requirements.txt -q

echo "  ✅ Dependencies installed"

# --------------------------------------------------
# 3. Generate synthetic data (Step 2)
# --------------------------------------------------
echo ""
echo "[3/7] Generating synthetic data..."
python generate_data.py
echo "  ✅ 4 CSV files generated in backend/data/"

# --------------------------------------------------
# 4. Normalize into SQLite (Step 3)
# --------------------------------------------------
echo ""
echo "[4/7] Running normalization..."
python normalize.py

# --------------------------------------------------
# 5. Run ML models (Step 4)
# --------------------------------------------------
echo ""
echo "[5/7] Running ML pipeline (9 models)..."
python run_models.py

# --------------------------------------------------
# 6. Run LLM reasoning (Step 5)
# --------------------------------------------------
echo ""
echo "[6/7] Running reasoning layer..."
if [ -n "$ANTHROPIC_API_KEY" ]; then
    echo "  ANTHROPIC_API_KEY detected — will call Claude API"
else
    echo "  No ANTHROPIC_API_KEY — using pre-composed explanations"
    echo "  To enable: export ANTHROPIC_API_KEY=sk-ant-..."
fi
python reason.py

# --------------------------------------------------
# 7. Run agent mock actions (Step 8)
# --------------------------------------------------
echo ""
echo "[7/7] Running agent mock actions..."
python agent.py

# --------------------------------------------------
# Start API server
# --------------------------------------------------
echo ""
echo "=============================================="
echo "  VEKTOR backend ready"
echo "=============================================="
echo ""
echo "  Starting API server on http://localhost:8000"
echo ""
echo "  Endpoints:"
echo "    GET  /health-score"
echo "    GET  /signals"
echo "    GET  /signals/{entity_id}"
echo "    GET  /mock-actions/{signal_id}"
echo "    POST /mock-actions"
echo ""
echo "  Press Ctrl+C to stop."
echo ""

python api.py
