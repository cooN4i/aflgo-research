#!/usr/bin/env bash
# ==============================================================================
# Build script for Target 5: libssh2 (packet_length wrap)
# Supports two-pass instrumentation for Directed Fuzzers
# ==============================================================================
set -euo pipefail

export ASAN_OPTIONS="abort_on_error=1:detect_leaks=0:use_sigaltstack=0"

MODE="${1:-all}"
SRC_DIR="${SRC_DIR:-/src/libssh2}"
OUT_DIR="${OUT_DIR:-/out}"
WORK_DIR="${WORK_DIR:-/work}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Ensure OpenSSL crypto dev library is installed
if ! dpkg -s libssl-dev >/dev/null 2>&1; then
    apt-get update && apt-get install -y libssl-dev
fi

export CC="afl-clang-fast"
export CXX="afl-clang-fast++"

mkdir -p "$OUT_DIR" "$WORK_DIR"

cd "$SRC_DIR"

# Set target lines for Directed Fuzzers (CVE-2026-55200 packet_length wrap in transport.c)
echo "transport.c:539" > "$WORK_DIR/BBtargets.txt"
echo "transport.c:542" >> "$WORK_DIR/BBtargets.txt"
echo "transport.c:560" >> "$WORK_DIR/BBtargets.txt"
echo "transport.c:561" >> "$WORK_DIR/BBtargets.txt"
echo "transport.c:567" >> "$WORK_DIR/BBtargets.txt"
echo "transport.c:580" >> "$WORK_DIR/BBtargets.txt"
echo "transport.c:585" >> "$WORK_DIR/BBtargets.txt"

if [ "$MODE" = "pass1" ] || [ "$MODE" = "all" ]; then
    if [ -n "${DAFL:-}" ]; then
        echo "[*] DAFL detected (single-pass selective fuzzer): skipping Pass 1 CFG extraction."
    else
        echo "[*] Starting Pass 1: CFG / CallGraph Extraction for libssh2..."
        
        rm -rf build || true

        if [ -n "${AFLGO:-}" ]; then
            export ADDITIONAL="-g -fno-omit-frame-pointer -targets=$WORK_DIR/BBtargets.txt -outdir=$WORK_DIR -flto -fuse-ld=gold -Wl,-plugin-opt=save-temps"
        elif [ -n "${FF_AFL:-}" ]; then
            export ADDITIONAL="-g -fno-omit-frame-pointer -pmode=origin -flto -fuse-ld=gold -Wl,-plugin-opt=save-temps"
        elif [ -n "${WINDRANGER:-}" ]; then
            export ADDITIONAL="-g -fno-omit-frame-pointer -flto -fuse-ld=gold -Wl,-plugin-opt=save-temps"
        else
            export ADDITIONAL="-g -fno-omit-frame-pointer"
        fi
        export CFLAGS="-g -fno-omit-frame-pointer ${CFLAGS:-} $ADDITIONAL"
        export CXXFLAGS="-g -fno-omit-frame-pointer ${CXXFLAGS:-} $ADDITIONAL"

        cmake -B build -DBUILD_SHARED_LIBS=OFF -DBUILD_EXAMPLES=OFF -DBUILD_TESTING=OFF \
              -DENABLE_ZLIB_COMPRESSION=OFF -DCRYPTO_BACKEND=OpenSSL -DCMAKE_BUILD_TYPE=RelWithDebInfo
        cmake --build build -j"$(nproc)"
        
        # Locate harness.c
        HARNESS_SRC="$SCRIPT_DIR/harness.c"
        if [ ! -f "$HARNESS_SRC" ] && [ -f "/recipe/harness.c" ]; then
            HARNESS_SRC="/recipe/harness.c"
        fi

        # Link harness in Pass 1 so LTO produces libssh2_harness.0.0.preopt.bc
        $CC $CFLAGS "$HARNESS_SRC" "$SRC_DIR/build/src/libssh2.a" -I"$SRC_DIR/include" -I"$SRC_DIR/src" -lcrypto -lssl -lpthread -o "$WORK_DIR/libssh2_harness"
        
        echo "[*] Pass 1 complete. Graphs generated in $WORK_DIR"
    fi
fi

if [ "$MODE" = "distance" ] || [ "$MODE" = "all" ]; then
    if [ -n "${AFLGO:-}" ] && [ -f "$AFLGO/distance/gen_distance_fast.py" ]; then
        echo "[*] Calculating distances using AFLGo ($AFLGO)..."
        if [ -f "$WORK_DIR/BBcalls.txt" ]; then
            awk -F',' 'NF==2 && $1!="" && $2!=""' "$WORK_DIR/BBcalls.txt" > "$WORK_DIR/BBcalls.txt.clean" && mv "$WORK_DIR/BBcalls.txt.clean" "$WORK_DIR/BBcalls.txt"
        fi
        if [ ! -s "$WORK_DIR/Ftargets.txt" ]; then
            echo "_libssh2_transport_read" > "$WORK_DIR/Ftargets.txt"
        fi
        BC_DIR="$WORK_DIR"
        if ! ls "$BC_DIR"/*.0.0.*.bc 1>/dev/null 2>&1; then
            if ls "$SRC_DIR"/*.0.0.*.bc 1>/dev/null 2>&1; then
                BC_DIR="$SRC_DIR"
            fi
        fi
        python3 "$AFLGO/distance/gen_distance_fast.py" "$BC_DIR" "$WORK_DIR" libssh2_harness
        echo "[*] Distance calculation complete: $WORK_DIR/distance.cfg.txt"
    elif [ -n "${FF_AFL:-}" ] && [ -f "$FF_AFL/scripts/gen_initial_distance.py" ]; then
        echo "[*] Calculating distances using FishFuzz ($FF_AFL)..."
        python3 "$FF_AFL/scripts/gen_initial_distance.py" "$WORK_DIR" || true
    elif [ -n "${WINDRANGER:-}" ]; then
        echo "[*] Processing Deviation Basic Blocks with WindRanger ($WINDRANGER)..."
        BC_FILE=$(find "$SRC_DIR" "$WORK_DIR" -name "*libssh2_harness*preopt.bc" -o -name "*preopt.bc" | head -n 1 || true)
        if [ -n "$BC_FILE" ] && [ -f "$BC_FILE" ]; then
            cbi --targets="$WORK_DIR/BBtargets.txt" "$BC_FILE" || true
            cp distance.txt condition_info.txt targets.txt "$OUT_DIR/" 2>/dev/null || true
            cp distance.txt condition_info.txt targets.txt "$WORK_DIR/" 2>/dev/null || true
        fi
    fi
fi

if [ "$MODE" = "pass2" ] || [ "$MODE" = "all" ]; then
    echo "[*] Starting Pass 2: Final Binary Instrumentation with ASan..."
    
    cd "$SRC_DIR"
    rm -rf build || true

    if [ -n "${AFLGO:-}" ]; then
        DISTANCE_FILE="$WORK_DIR/distance.cfg.txt"
        if [ ! -f "$DISTANCE_FILE" ]; then
            touch "$DISTANCE_FILE"
        fi
        export CFLAGS="-distance=$DISTANCE_FILE -fsanitize=address"
        export CXXFLAGS="-distance=$DISTANCE_FILE -fsanitize=address"
    elif [ -n "${FF_AFL:-}" ]; then
        export CFLAGS="-pmode=origin -fsanitize=address"
        export CXXFLAGS="-pmode=origin -fsanitize=address"
    else
        export CFLAGS="-fsanitize=address"
        export CXXFLAGS="-fsanitize=address"
    fi
    export LDFLAGS="-fsanitize=address"

    cmake -B build -DBUILD_SHARED_LIBS=OFF -DBUILD_EXAMPLES=OFF -DBUILD_TESTING=OFF \
          -DENABLE_ZLIB_COMPRESSION=OFF -DCRYPTO_BACKEND=OpenSSL -DCMAKE_BUILD_TYPE=RelWithDebInfo
    cmake --build build -j"$(nproc)"

    # Locate harness.c
    HARNESS_SRC="$SCRIPT_DIR/harness.c"
    if [ ! -f "$HARNESS_SRC" ] && [ -f "/recipe/harness.c" ]; then
        HARNESS_SRC="/recipe/harness.c"
    fi

    # Compile the standalone fuzz harness linking against libssh2.a
    $CC $CFLAGS "$HARNESS_SRC" "$SRC_DIR/build/src/libssh2.a" -I"$SRC_DIR/include" -I"$SRC_DIR/src" -lcrypto -lssl -lpthread -o "$OUT_DIR/libssh2_packet"
    echo "[+] Successfully built instrumented binary: $OUT_DIR/libssh2_packet"
fi
