# DGF Benchmark (Directed Greybox Fuzzing)

Comparative evaluation benchmark for Directed Greybox Fuzzers:
1. **`aflgo_orig`** — Vanilla AFLGo baseline (CCS '17)
2. **`aflgo_mod`** — Complexity weighting & dominator scaling (Research Candidate)
3. **`dafl`** — Selective instrumentation & scoring (USENIX Security '23)
4. **`fishfuzz`** — Multi-distance & dynamic target ranking (USENIX Security '23)
5. **`windranger`** — Deviation basic blocks DBB (ICSE '22)

All target vulnerabilities come exclusively from `bikini/exploitarium` (Binutils objdump, FFmpeg, VLC, c-ares, libssh2).

---

## Quickstart

### Prerequisites
- Docker Engine / Docker Desktop
- Python 3.8+

### 1. Install Python dependencies
```bash
pip install -r requirements.txt
```

### 2. Verify configuration
```bash
python bench.py info
```

### 3. Build Docker images & compile targets
```bash
# Build base Docker image
python bench.py build --base

# Build all 5 fuzzer Docker images (pulled from GitHub/web)
python bench.py build --fuzzer aflgo_mod
python bench.py build --fuzzer aflgo_orig
python bench.py build --fuzzer dafl
python bench.py build --fuzzer fishfuzz
python bench.py build --fuzzer windranger

# Or build everything (images + targets):
python bench.py build --all
```

### 4. Run Fuzzing Trials
```bash
# Test run (1 trial, 10 minutes)
python bench.py run --target objdump_dlx --fuzzer aflgo_mod --trials 1 --duration 10m

# Full benchmark campaign
python bench.py run --trials 5 --duration 12h --workers 4
```

### 5. Statistical Analysis
```bash
python bench.py analyze
```
Calculates Mann-Whitney U test p-values, Vargha-Delaney A12 effect sizes, median/IQR Time-To-Target (TTT), and generates convergence plots in `storage/plots/`.
