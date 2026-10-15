#!/usr/bin/env bash
# ==============================================================================
# Build script for Target 5: libssh2 (packet_length wrap)
# Supports two-pass instrumentation for Directed Fuzzers
# ==============================================================================
set -euo pipefail

MODE="${1:-all}"
SRC_DIR="${SRC_DIR:-/src/libssh2}"
OUT_DIR="${OUT_DIR:-/out}"
WORK_DIR="${WORK_DIR:-/work}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

export CC="${CC:-afl-clang-fast}"
export CXX="${CXX:-afl-clang-fast++}"

mkdir -p "$OUT_DIR" "$WORK_DIR"

cd "$SRC_DIR"

# Set target lines for Directed Fuzzers
echo "transport.c:85" > "$WORK_DIR/BBtargets.txt"

if [ "$MODE" = "pass1" ] || [ "$MODE" = "all" ]; then
    echo "[*] Starting Pass 1: CFG / CallGraph Extraction for libssh2..."
    
    rm -rf build || true

    export ADDITIONAL="-targets=$WORK_DIR/BBtargets.txt -outdir=$WORK_DIR -flto -fuse-ld=gold -Wl,-plugin-opt=save-temps"
    export CFLAGS="${CFLAGS:-} $ADDITIONAL"
    export CXXFLAGS="${CXXFLAGS:-} $ADDITIONAL"

    cmake -B build -DBUILD_SHARED_LIBS=OFF -DBUILD_EXAMPLES=OFF -DBUILD_TESTING=OFF -DENABLE_ZLIB_COMPRESSION=OFF
    cmake --build build -j"$(nproc)"
    
    # Link harness in Pass 1 so LTO produces libssh2_harness.0.0.preopt.bc
    $CC $CFLAGS "$SCRIPT_DIR/harness.c" "$SRC_DIR/build/src/libssh2.a" -I"$SRC_DIR/include" -I"$SRC_DIR/src" -lcrypto -lssl -lpthread -o "$WORK_DIR/libssh2_harness"
    
    echo "[*] Pass 1 complete. Graphs generated in $WORK_DIR"
fi

if [ "$MODE" = "distance" ] || [ "$MODE" = "all" ]; then
    if [ -n "${AFLGO:-}" ] && [ -f "$AFLGO/distance/gen_distance_fast.py" ]; then
        echo "[*] Calculating distances using AFLGo ($AFLGO)..."
        python3 "$AFLGO/distance/gen_distance_fast.py" "$WORK_DIR" "$WORK_DIR" libssh2_harness
        echo "[*] Distance calculation complete: $WORK_DIR/distance.cfg.txt"
    elif [ -n "${FF_AFL:-}" ] && [ -f "$FF_AFL/scripts/gen_initial_distance.py" ]; then
        echo "[*] Calculating distances using FishFuzz ($FF_AFL)..."
        python3 "$FF_AFL/scripts/gen_initial_distance.py" -t "$WORK_DIR" || true
    elif [ -n "${WINDRANGER:-}" ]; then
        echo "[*] Processing Deviation Basic Blocks with WindRanger ($WINDRANGER)..."
        if [ -f "$WORK_DIR/libssh2_harness.0.0.preopt.bc" ]; then
            cbi --targets="$WORK_DIR/BBtargets.txt" "$WORK_DIR/libssh2_harness.0.0.preopt.bc" || true
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

    cmake -B build -DBUILD_SHARED_LIBS=OFF -DBUILD_EXAMPLES=OFF -DBUILD_TESTING=OFF -DENABLE_ZLIB_COMPRESSION=OFF
    cmake --build build -j"$(nproc)"

    # Compile the standalone fuzz harness linking against libssh2.a
    $CC $CFLAGS "$SCRIPT_DIR/harness.c" "$SRC_DIR/build/src/libssh2.a" -I"$SRC_DIR/include" -I"$SRC_DIR/src" -lcrypto -lssl -lpthread -o "$OUT_DIR/libssh2_packet"
    echo "[+] Successfully built instrumented binary: $OUT_DIR/libssh2_packet"
fi
