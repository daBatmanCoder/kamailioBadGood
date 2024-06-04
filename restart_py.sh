#!/bin/bash

# Find the process ID of the script
PID=$(ps -ef | grep 'python3 blockchain_server.py' | grep -v grep | awk '{print $2}')

# Kill the process if it is running
if [ ! -z "$PID" ]; then
    kill $PID
fi

# Wait a bit to ensure the process has been terminated
sleep 2

# Delete existing output log files
rm -f output_*.out

# Restart the script and redirect output to a new file
nohup python3 blockchain_server.py > output_$(date +"%Y%m%d_%H%M%S").out 2>&1 &
