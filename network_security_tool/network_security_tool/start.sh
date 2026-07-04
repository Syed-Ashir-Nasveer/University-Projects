#!/bin/bash

# Network Security Tool - Quick Start Script

echo "🛡️  Network Security Tool - Quick Start"
echo "========================================"
echo ""

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m'

# Check Python
echo -e "${BLUE}[1/4] Checking Python installation...${NC}"
if command -v python3 &> /dev/null; then
    PYTHON_VERSION=$(python3 --version)
    echo -e "${GREEN}✓ Found $PYTHON_VERSION${NC}"
else
    echo -e "${RED}✗ Python 3 not found${NC}"
    exit 1
fi

# Create venv
echo -e "\n${BLUE}[2/4] Creating virtual environment...${NC}"
python3 -m venv venv
source venv/bin/activate
echo -e "${GREEN}✓ Virtual environment activated${NC}"

# Install dependencies
echo -e "\n${BLUE}[3/4] Installing dependencies...${NC}"
pip install -q --upgrade pip
pip install -q -r requirements.txt
echo -e "${GREEN}✓ Dependencies installed${NC}"

# Run application
echo -e "\n${BLUE}[4/4] Starting application...${NC}"
echo -e "${GREEN}✓ Launching Network Security Tool${NC}"
echo ""
echo "========================================"
echo ""

python3 main.py
