#!/bin/bash
python scripts/for_dep/check_requirements.py requirements.txt
if [ $? -eq 1 ]
then
    echo Installing missing packages...
    pip install -r requirements.txt
fi
python -m swarmnat $@
#read -p "Press any key to continue..."
