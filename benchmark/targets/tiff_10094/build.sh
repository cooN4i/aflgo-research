#!/usr/bin/env bash
# ==============================================================================
# Build script for libtiff tiff2ps (CVE-2016-10094)
# ==============================================================================
set -euo pipefail

MODE="${1:-all}"  # "pass1", "pass2", or "all"
SRC_DIR="${SRC_DIR:-/src/tiff_10094}"
OUT_DIR="${OUT_DIR:-/out}"
WORK_DIR="${WORK_DIR:-/work}"

export PATH="/usr/lib/llvm-11/bin:${PATH}"
if [ ! -f /usr/bin/opt ] && [ -f /usr/lib/llvm-11/bin/opt ]; then
    ln -sf /usr/lib/llvm-11/bin/opt /usr/bin/opt 2>/dev/null || true
fi

chmod -R +x /fuzzer 2>/dev/null || true
export ASAN_OPTIONS="abort_on_error=1:detect_leaks=0:use_sigaltstack=0"

if [ -z "${AFL_PATH:-}" ]; then
    if [ -d "/fuzzer/dafl" ]; then export AFL_PATH="/fuzzer/dafl"; fi
    if [ -d "/fuzzer/WindRanger/fuzz" ]; then export AFL_PATH="/fuzzer/WindRanger/fuzz"; fi
    if [ -d "/fuzzer/fishfuzz/FF_AFL" ]; then export AFL_PATH="/fuzzer/fishfuzz/FF_AFL"; fi
    if [ -d "/fuzzer/aflgo-mod/instrument" ]; then export AFL_PATH="/fuzzer/aflgo-mod/instrument"; fi
    if [ -d "/fuzzer/aflgo-orig/instrument" ]; then export AFL_PATH="/fuzzer/aflgo-orig/instrument"; fi
fi

if [ -z "${AFLGO:-}" ]; then
    if [ -d "/fuzzer/aflgo-mod" ]; then export AFLGO="/fuzzer/aflgo-mod"; fi
    if [ -d "/fuzzer/aflgo-orig" ]; then export AFLGO="/fuzzer/aflgo-orig"; fi
fi

export CC="afl-clang-fast"
export CXX="afl-clang-fast++"

mkdir -p "$OUT_DIR" "$WORK_DIR"
cd "$SRC_DIR"

# Target basic block for CVE-2016-10094 in tiff2ps.c:2543 (PSDataPalette)
cat << 'EOF' > "$WORK_DIR/BBtargets.txt"
tiff2ps.c:2543
tiff2ps.c:2544
tiff2ps.c:2558
EOF

if [ "$MODE" = "pass1" ] || [ "$MODE" = "all" ]; then
    if [ -n "${DAFL:-}" ]; then
        echo "[*] DAFL detected (single-pass selective fuzzer): skipping Pass 1 CFG extraction."
    else
        echo "[*] Starting Pass 1: CFG / CallGraph Extraction..."
        make clean || true
        make distclean || true

        if [ -n "${AFLGO:-}" ]; then
            export ADDITIONAL="-targets=$WORK_DIR/BBtargets.txt -outdir=$WORK_DIR -flto -fuse-ld=gold -Wl,-plugin-opt=save-temps"
        elif [ -n "${FF_AFL:-}" ]; then
            export ADDITIONAL="-pmode=origin -flto -fuse-ld=gold -Wl,-plugin-opt=save-temps"
        elif [ -n "${WINDRANGER:-}" ]; then
            export ADDITIONAL="-flto -fuse-ld=gold -Wl,-plugin-opt=save-temps"
        else
            export ADDITIONAL=""
        fi
        export CFLAGS="-g -Wno-error $ADDITIONAL"
        export CXXFLAGS="-g -Wno-error $ADDITIONAL"

        ./autogen.sh || true
        ./configure --disable-shared --prefix="$WORK_DIR/install"

        make -C port clean || true
        make -C libtiff clean || true
        make -C tools clean || true
        make -C port -j"$(nproc)"
        make -C libtiff -j"$(nproc)"
        make -C tools tiff2ps -j"$(nproc)"
        echo "[*] Pass 1 complete. Graphs generated in $WORK_DIR"
    fi
fi

if [ "$MODE" = "distance" ] || [ "$MODE" = "all" ]; then
    if [ -n "${AFLGO:-}" ] && [ -f "$AFLGO/distance/gen_distance_fast.py" ]; then
        echo "[*] Calculating distances using AFLGo ($AFLGO)..."
        if [ -f "$WORK_DIR/BBcalls.txt" ]; then
            awk -F',' 'NF==2 && $1!="" && $2!=""' "$WORK_DIR/BBcalls.txt" > "$WORK_DIR/BBcalls.txt.clean" && mv "$WORK_DIR/BBcalls.txt.clean" "$WORK_DIR/BBcalls.txt"
        fi
        python3 "$AFLGO/distance/gen_distance_fast.py" "$SRC_DIR/tools" "$WORK_DIR" tiff2ps
        echo "[*] Distance calculation complete: $WORK_DIR/distance.cfg.txt"
    elif [ -n "${FF_AFL:-}" ] && [ -f "$FF_AFL/scripts/gen_initial_distance.py" ]; then
        echo "[*] Calculating distances using FishFuzz ($FF_AFL)..."
        python3 "$FF_AFL/scripts/gen_initial_distance.py" -t "$WORK_DIR" || true
    elif [ -n "${WINDRANGER:-}" ]; then
        echo "[*] Processing Deviation Basic Blocks with WindRanger ($WINDRANGER)..."
        if [ -f "$SRC_DIR/tools/tiff2ps.0.0.preopt.bc" ]; then
            cbi --targets="$WORK_DIR/BBtargets.txt" "$SRC_DIR/tools/tiff2ps.0.0.preopt.bc" || true
            cp distance.txt condition_info.txt targets.txt "$OUT_DIR/" 2>/dev/null || true
            cp distance.txt condition_info.txt targets.txt "$WORK_DIR/" 2>/dev/null || true
        fi
    fi
fi

if [ "$MODE" = "pass2" ] || [ "$MODE" = "all" ]; then
    echo "[*] Starting Pass 2: Binary Instrumentation..."
    cd "$SRC_DIR"
    make clean || true
    make distclean || true
    find . -name "config.cache" -delete 2>/dev/null || true

    if [ -n "${AFLGO:-}" ]; then
        DISTANCE_FILE="$WORK_DIR/distance.cfg.txt"
        if [ ! -f "$DISTANCE_FILE" ]; then
            echo "[!] Warning: $DISTANCE_FILE not found. Creating empty distance file."
            touch "$DISTANCE_FILE"
        fi
        export CFLAGS="-g -fsanitize=address -Wno-error -distance=$DISTANCE_FILE"
        export CXXFLAGS="-g -fsanitize=address -Wno-error -distance=$DISTANCE_FILE"
    elif [ -n "${FF_AFL:-}" ]; then
        export CFLAGS="-g -fsanitize=address -Wno-error -pmode=origin"
        export CXXFLAGS="-g -fsanitize=address -Wno-error -pmode=origin"
    else
        export CFLAGS="-g -fsanitize=address -Wno-error"
        export CXXFLAGS="-g -fsanitize=address -Wno-error"
    fi

    ./autogen.sh || true
    ./configure --disable-shared --prefix="$WORK_DIR/install"

    make -C port -j"$(nproc)"
    make -C libtiff -j"$(nproc)"
    make -C tools tiff2ps -j"$(nproc)"

    cp "$SRC_DIR/tools/tiff2ps" "$OUT_DIR/tiff_10094"
    echo "[+] Successfully built instrumented binary: $OUT_DIR/tiff_10094"
fi
