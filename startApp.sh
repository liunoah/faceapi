#!/bin/bash

while true; do
    if ! ps -aux | grep -q "[n]ode app.js"; then
        echo "app.js is not running. Starting..."
        nohup node app.js &
    fi
    sleep 1
done
