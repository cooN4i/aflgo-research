#!/usr/bin/env bash
# ==============================================================================
# Build script for Target 4: c-ares DNS Library (UAF)
# Supports two-pass instrumentation for Directed Fuzzers
# ==============================================================================
set -euo pipefail

MODE="${1:-all}"
SRC_DIR="${SRC_DIR:-/src/c-ares}"
OUT_DIR="${OUT_DIR:-/out}"
WORK_DIR="${WORK_DIR:-/work}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

export CC="${CC:-afl-clang-fast}"
export CXX="${CXX:-afl-clang-fast++}"

mkdir -p "$OUT_DIR" "$WORK_DIR"

cd "$SRC_DIR"

# Set target lines for Directed Fuzzers
echo "ares_process.c:480" > "$WORK_DIR/BBtargets.txt"

if [ "$MODE" = "pass1" ] || [ "$MODE" = "all" ]; then
    echo "[*] Starting Pass 1: CFG / CallGraph Extraction for c-ares..."
    
    rm -rf build || true

    export ADDITIONAL="-targets=$WORK_DIR/BBtargets.txt -outdir=$WORK_DIR -flto -fuse-ld=gold -Wl,-plugin-opt=save-temps"
    export CFLAGS="${CFLAGS:-} $ADDITIONAL"
    export CXXFLAGS="${CXXFLAGS:-} $ADDITIONAL"

    cmake -B build -DCARES_STATIC=ON -DCARES_SHARED=OFF -DCARES_BUILD_TESTS=OFF -DCARES_BUILD_TOOLS=OFF
    cmake --build build -j"$(nproc)"
    
    # Link harness in Pass 1 so LTO produces cares_harness.0.0.preopt.bc
    $CC $CFLAGS "$SCRIPT_DIR/harness.c" "$SRC_DIR/build/lib/libcares.a" -I"$SRC_DIR/include" -lpthread -o "$WORK_DIR/cares_harness"
    
    echo "[*] Pass 1 complete. Graphs generated in $WORK_DIR"
fi

if [ "$MODE" = "distance" ] || [ "$MODE" = "all" ]; then
    if [ -n "${AFLGO:-}" ] && [ -f "$AFLGO/distance/gen_distance_fast.py" ]; then
        echo "[*] Calculating distances using AFLGo ($AFLGO)..."
        python3 "$AFLGO/distance/gen_distance_fast.py" "$WORK_DIR" "$WORK_DIR" cares_harness
        echo "[*] Distance calculation complete: $WORK_DIR/distance.cfg.txt"
    elif [ -n "${FF_AFL:-}" ] && [ -f "$FF_AFL/scripts/gen_initial_distance.py" ]; then
        echo "[*] Calculating distances using FishFuzz ($FF_AFL)..."
        python3 "$FF_AFL/scripts/gen_initial_distance.py" -t "$WORK_DIR" || true
    elif [ -n "${WINDRANGER:-}" ]; then
        echo "[*] Processing Deviation Basic Blocks with WindRanger ($WINDRANGER)..."
        if [ -f "$WORK_DIR/cares_harness.0.0.preopt.bc" ]; then
            cbi --targets="$WORK_DIR/BBtargets.txt" "$WORK_DIR/cares_harness.0.0.preopt.bc" || true
        fi
    fi
fi

if [ "$MODE" = "pass2" ] || [ "$MODE" = "all" ]; then
    echo "[*] Starting Pass 2: Final Binary Instrumentation with ASan..."
    
    cd "$SRC_DIR"
    rm -rf build || true

    DISTANCE_FILE="$WORK_DIR/distance.cfg.txt"
    if [ ! -f "$DISTANCE_FILE" ]; then
        touch "$DISTANCE_FILE"
    fi

    export CFLAGS="${CFLAGS:-} -distance=$DISTANCE_FILE -fsanitize=address"
    export CXXFLAGS="${CXXFLAGS:-} -distance=$DISTANCE_FILE -fsanitize=address"
    export LDFLAGS="${LDFLAGS:-} -fsanitize=address"

    cmake -B build -DCARES_STATIC=ON -DCARES_SHARED=OFF -DCARES_BUILD_TESTS=OFF -DCARES_BUILD_TOOLS=OFF
    cmake --build build -j"$(nproc)"

    # Compile the standalone fuzz harness linking against libcares.a
    $CC $CFLAGS "$SCRIPT_DIR/harness.c" "$SRC_DIR/build/lib/libcares.a" -I"$SRC_DIR/include" -lpthread -o "$OUT_DIR/cares_tcp"
    echo "[+] Successfully built instrumented binary: $OUT_DIR/cares_tcp"
fi
