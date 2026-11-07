#!/usr/bin/env bash
set -e

echo "=================================================================="
echo " Starting DGF Benchmark Orchestrator"
echo "=================================================================="

# Check docker socket
if ! docker info >/dev/null 2>&1; then
    echo "[!] Error: Cannot connect to Docker daemon via /var/run/docker.sock"
    echo "    Make sure the docker socket is mounted: -v /var/run/docker.sock:/var/run/docker.sock"
    exit 1
fi

echo "[*] Step 1: Building fuzzer base and images if needed..."
python3 bench.py build --base
python3 bench.py build --all

echo "[*] Step 2: Running benchmark trials according to config.yaml..."
python3 bench.py run

echo "[*] Step 3: Running statistical analysis (TTT / TTE, Mann-Whitney, A12)..."
python3 bench.py analyze || true

echo "[*] Step 4: Packaging final results..."
rm -f results.tar.gz
tar -czf results.tar.gz storage/runs storage/plots config.yaml

echo "=================================================================="
echo " [SUCCESS] Benchmark finished successfully!"
echo " Results packaged to: results.tar.gz"
echo "=================================================================="

