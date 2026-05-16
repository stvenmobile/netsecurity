#!/bin/bash
# Move to the project directory
cd /home/steve/netsecurity

# Activate the virtual environment
source .venv/bin/activate

# Run the analysis and generate the PDF
python3 analyze_logs.py
