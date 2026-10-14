
#!/bin/bash

cd "$HOME/soc-bruteforce-detection" || exit 1

while true; do
    echo "===== Check: $(date) ====="
    sudo -n python3 live_detector.py
    sleep 30
done
