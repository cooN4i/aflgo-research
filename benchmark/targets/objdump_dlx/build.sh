#!/usr/bin/env bash
# ==============================================================================
# Build script for Target 1: GNU Binutils objdump (DLX ELF)
# Supports two-pass instrumentation for AFLGo / AFLGo-mod and WindRanger
# ==============================================================================
set -euo pipefail

export ASAN_OPTIONS="abort_on_error=1:detect_leaks=0:use_sigaltstack=0"

MODE="${1:-all}"  # "pass1", "pass2", or "all"
SRC_DIR="${SRC_DIR:-/src/binutils-gdb}"
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

# Set target lines for Directed Fuzzers
echo "elf32-dlx.c:551" > "$WORK_DIR/BBtargets.txt"
echo "elf32-dlx.c:544" >> "$WORK_DIR/BBtargets.txt"

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
        export CFLAGS="${CFLAGS:-} $ADDITIONAL"
        export CXXFLAGS="${CXXFLAGS:-} $ADDITIONAL"

        ./configure --target=dlx-elf \
                    --disable-shared \
                    --disable-gdb \
                    --disable-libdecnumber \
                    --disable-readline \
                    --disable-sim \
                    --disable-nls \
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
        python3 "$AFLGO/distance/gen_distance_fast.py" "$SRC_DIR/binutils" "$WORK_DIR" objdump
        echo "[*] Distance calculation complete: $WORK_DIR/distance.cfg.txt"
    elif [ -n "${FF_AFL:-}" ] && [ -f "$FF_AFL/scripts/gen_initial_distance.py" ]; then
        echo "[*] Calculating distances using FishFuzz ($FF_AFL)..."
        python3 "$FF_AFL/scripts/gen_initial_distance.py" -t "$WORK_DIR" || true
    elif [ -n "${WINDRANGER:-}" ]; then
        echo "[*] Processing Deviation Basic Blocks with WindRanger ($WINDRANGER)..."
        if [ -f "$SRC_DIR/binutils/objdump.0.0.preopt.bc" ]; then
            cbi --targets="$WORK_DIR/BBtargets.txt" "$SRC_DIR/binutils/objdump.0.0.preopt.bc" || true
            cp distance.txt condition_info.txt targets.txt "$OUT_DIR/" 2>/dev/null || true
            cp distance.txt condition_info.txt targets.txt "$WORK_DIR/" 2>/dev/null || true
        fi
    fi
fi

if [ "$MODE" = "pass2" ] || [ "$MODE" = "all" ]; then
    echo "[*] Starting Pass 2: Binary Instrumentation..."
    
    # Clean previous build artifacts
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

    ./configure --target=dlx-elf \
                --disable-shared \
                --disable-gdb \
                --disable-libdecnumber \
                --disable-readline \
                --disable-sim \
                --disable-nls \
                --prefix="$WORK_DIR/install"

    make -j"$(nproc)" all-binutils

    # Copy final instrumented binary to output directory
    cp "$SRC_DIR/binutils/objdump" "$OUT_DIR/objdump_dlx"
    echo "[+] Successfully built instrumented binary: $OUT_DIR/objdump_dlx"
fi
