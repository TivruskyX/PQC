#!/bin/bash
# Setup script for Post-Quantum OIDC environment

# Create virtual environment if it doesn't exist
if [ ! -d "venv" ]; then
    echo "Creating virtual environment..."
    python3 -m venv venv
fi

# Set library paths for both system-wide and local installations
export LD_LIBRARY_PATH=/usr/local/lib:$HOME/.local/lib:$LD_LIBRARY_PATH
export PYTHONPATH=$PWD:$PYTHONPATH

source venv/bin/activate

# Upgrade pip
pip install --upgrade pip > /dev/null 2>&1

# Install requirements
echo "Installing Python dependencies..."
pip install -r requirements.txt > /dev/null 2>&1

echo "✓ Post-Quantum OIDC environment activated"
echo "  - liboqs library path set"
echo "  - Python virtual environment activated"
echo ""
echo "You can now run:"
echo "  python ui/app.py                         # Launch web interface"
echo "  python src/pq_crypto/test_crypto.py     # Test PQ cryptography"
echo "  python -m src.benchmarks.run_benchmarks  # Generate benchmarks"
