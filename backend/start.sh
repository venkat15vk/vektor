#!/bin/bash
echo "=== Running VEKTOR pipeline ==="
echo "Step 1: Normalize..."
python3 normalize.py
echo "Step 2: Run models..."
python3 run_models.py
echo "Step 3: Reason..."
python3 reason.py
echo "Step 4: Starting API..."
python3 api.py
