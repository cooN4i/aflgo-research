#!/usr/bin/env bash
# ==============================================================================
# Build script for Canonical DGF Benchmark: GNU Binutils cxxfilt (CVE-2016-4487)
# Evaluated in AFLGo (CCS'17), WindRanger (ICSE'20), DAFL (USENIX'23), FishFuzz (USENIX'23)
# ==============================================================================
set -euo pipefail

MODE="${1:-all}"  # "pass1", "pass2", or "all"
SRC_DIR="${SRC_DIR:-/src/cxxfilt}"
OUT_DIR="${OUT_DIR:-/out}"
WORK_DIR="${WORK_DIR:-/work}"

export PATH="/usr/lib/llvm-11/bin:${PATH}"
if [ ! -f /usr/bin/opt ] && [ -f /usr/lib/llvm-11/bin/opt ]; then
    ln -sf /usr/lib/llvm-11/bin/opt /usr/bin/opt 2>/dev/null || true
fi

if [ -z "${AFL_PATH:-}" ]; then
    if [ -d "/fuzzer/dafl" ]; then export AFL_PATH="/fuzzer/dafl"; fi
    if [ -d "/fuzzer/WindRanger/fuzz" ]; then export AFL_PATH="/fuzzer/WindRanger/fuzz"; fi
    if [ -d "/fuzzer/fishfuzz/FF_AFL" ]; then export AFL_PATH="/fuzzer/fishfuzz/FF_AFL"; fi
    if [ -d "/fuzzer/aflgo-mod/instrument" ]; then export AFL_PATH="/fuzzer/aflgo-mod/instrument"; fi
    if [ -d "/fuzzer/aflgo-orig/instrument" ]; then export AFL_PATH="/fuzzer/aflgo-orig/instrument"; fi
fi

export CC="afl-clang-fast"
export CXX="afl-clang-fast++"

mkdir -p "$OUT_DIR" "$WORK_DIR"

cd "$SRC_DIR"

# Clean CRLF in case source was checked out on Windows
find . -type f \( -name "configure*" -o -name "*.sh" -o -name "*.in" -o -name "*.ac" -o -name "config.*" -o -name "mkinstalldirs" -o -name "install-sh" -o -name "depcomp" -o -name "compile" -o -name "move-if-change" -o -name "*.sed" \) | xargs sed -i 's/\r$//' 2>/dev/null || true

# Set canonical target lines for CVE-2016-4487
cat << 'EOF' > "$WORK_DIR/BBtargets.txt"
cplus-dem.c:4319
cplus-dem.c:2594
cplus-dem.c:1490
cplus-dem.c:1203
cplus-dem.c:886
cxxfilt.c:62
cxxfilt.c:227
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

        ./configure --disable-werror \
                    --disable-shared \
                    --disable-gdb \
                    --disable-libdecnumber \
                    --disable-readline \
                    --disable-sim \
                    --prefix="$WORK_DIR/install"

        make -j"$(nproc)" all-binutils
        echo "[*] Pass 1 complete. Graphs generated in $WORK_DIR"
    fi
fi

if [ "$MODE" = "distance" ] || [ "$MODE" = "all" ]; then
    if [ -n "${AFLGO:-}" ] && [ -f "$AFLGO/distance/gen_distance_fast.py" ]; then
        echo "[*] Calculating distances using AFLGo ($AFLGO)..."
        if [ -f "$WORK_DIR/BBcalls.txt" ]; then
            awk -F',' 'NF==2 && $1!="" && $2!=""' "$WORK_DIR/BBcalls.txt" > "$WORK_DIR/BBcalls.txt.clean" && mv "$WORK_DIR/BBcalls.txt.clean" "$WORK_DIR/BBcalls.txt"
        fi
        python3 "$AFLGO/distance/gen_distance_fast.py" "$SRC_DIR/binutils" "$WORK_DIR" cxxfilt
        echo "[*] Distance calculation complete: $WORK_DIR/distance.cfg.txt"
    elif [ -n "${FF_AFL:-}" ] && [ -f "$FF_AFL/scripts/gen_initial_distance.py" ]; then
        echo "[*] Calculating distances using FishFuzz ($FF_AFL)..."
        python3 "$FF_AFL/scripts/gen_initial_distance.py" -t "$WORK_DIR" || true
    elif [ -n "${WINDRANGER:-}" ]; then
        echo "[*] Processing Deviation Basic Blocks with WindRanger ($WINDRANGER)..."
        if [ -f "$SRC_DIR/binutils/cxxfilt.0.0.preopt.bc" ]; then
            cbi --targets="$WORK_DIR/BBtargets.txt" "$SRC_DIR/binutils/cxxfilt.0.0.preopt.bc" || true
            cp distance.txt condition_info.txt targets.txt "$OUT_DIR/" 2>/dev/null || true
            cp distance.txt condition_info.txt targets.txt "$WORK_DIR/" 2>/dev/null || true
        fi
    fi
fi

if [ "$MODE" = "pass2" ] || [ "$MODE" = "all" ]; then
    echo "[*] Starting Pass 2: Binary Instrumentation..."
    
    cd "$SRC_DIR"

# Clean CRLF in case source was checked out on Windows
find . -type f \( -name "configure*" -o -name "*.sh" -o -name "*.in" -o -name "*.ac" -o -name "config.*" -o -name "mkinstalldirs" -o -name "install-sh" -o -name "depcomp" -o -name "compile" -o -name "move-if-change" -o -name "*.sed" \) | xargs sed -i 's/\r$//' 2>/dev/null || true
    make clean || true
    make distclean || true
    find . -name "config.cache" -delete 2>/dev/null || true

    if [ -n "${AFLGO:-}" ]; then
        DISTANCE_FILE="$WORK_DIR/distance.cfg.txt"
        if [ ! -f "$DISTANCE_FILE" ]; then
            echo "[!] Warning: $DISTANCE_FILE not found. Creating empty distance file."
            touch "$DISTANCE_FILE"
        fi
        export CFLAGS="-g -Wno-error -distance=$DISTANCE_FILE"
        export CXXFLAGS="-g -Wno-error -distance=$DISTANCE_FILE"
    elif [ -n "${FF_AFL:-}" ]; then
        export CFLAGS="-g -Wno-error -pmode=origin"
        export CXXFLAGS="-g -Wno-error -pmode=origin"
    else
        export CFLAGS="-g -Wno-error"
        export CXXFLAGS="-g -Wno-error"
    fi

    ./configure --disable-werror \
                --disable-shared \
                --disable-gdb \
                --disable-libdecnumber \
                --disable-readline \
                --disable-sim \
                --prefix="$WORK_DIR/install"

    make -j"$(nproc)" all-binutils

    # Copy final instrumented binary to output directory
    cp "$SRC_DIR/binutils/cxxfilt" "$OUT_DIR/cxxfilt"
    echo "[+] Successfully built instrumented binary: $OUT_DIR/cxxfilt"
fi
