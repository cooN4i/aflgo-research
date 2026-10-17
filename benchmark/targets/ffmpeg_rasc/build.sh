#!/usr/bin/env bash
# ==============================================================================
# Build script for Target 2: FFmpeg RASC decoder
# Supports two-pass instrumentation for Directed Fuzzers
# ==============================================================================
set -euo pipefail

export ASAN_OPTIONS="abort_on_error=1:detect_leaks=0:use_sigaltstack=0"

MODE="${1:-all}"
SRC_DIR="${SRC_DIR:-/src/ffmpeg}"
OUT_DIR="${OUT_DIR:-/out}"
WORK_DIR="${WORK_DIR:-/work}"

export CC="afl-clang-fast"
export CXX="afl-clang-fast++"

mkdir -p "$OUT_DIR" "$WORK_DIR"

cd "$SRC_DIR"

# Set target lines for Directed Fuzzers
echo "rasc.c:288" > "$WORK_DIR/BBtargets.txt"
echo "rasc.c:291" >> "$WORK_DIR/BBtargets.txt"

if [ "$MODE" = "pass1" ] || [ "$MODE" = "all" ]; then
    if [ -n "${DAFL:-}" ]; then
        echo "[*] DAFL detected (single-pass selective fuzzer): skipping Pass 1 CFG extraction."
    else
        echo "[*] Starting Pass 1: CFG / CallGraph Extraction for FFmpeg..."
        
        make clean || true
        make distclean || true

        if [ -n "${AFLGO:-}" ]; then
            ADD_CFLAGS="-targets=$WORK_DIR/BBtargets.txt -outdir=$WORK_DIR -flto -fuse-ld=gold"
            ADD_LDFLAGS="-flto -fuse-ld=gold -Wl,-plugin-opt=save-temps"
        elif [ -n "${FF_AFL:-}" ]; then
            ADD_CFLAGS="-pmode=origin -flto -fuse-ld=gold"
            ADD_LDFLAGS="-flto -fuse-ld=gold -Wl,-plugin-opt=save-temps"
        elif [ -n "${WINDRANGER:-}" ]; then
            ADD_CFLAGS="-flto -fuse-ld=gold"
            ADD_LDFLAGS="-flto -fuse-ld=gold -Wl,-plugin-opt=save-temps"
        else
            ADD_CFLAGS=""
            ADD_LDFLAGS=""
        fi

        unset CFLAGS CXXFLAGS LDFLAGS

        ./configure --cc="$CC" --cxx="$CXX" \
                    --host-cc="clang" \
                    --extra-cflags="$ADD_CFLAGS" \
                    --extra-ldflags="$ADD_LDFLAGS" \
                    --disable-shared --enable-static \
                    --disable-x86asm \
                    --disable-doc --disable-programs --enable-ffmpeg \
                    --disable-everything --enable-decoder=rasc \
                    --enable-demuxer=avi --enable-protocol=file

        make -j"$(nproc)"
        
        echo "[*] Pass 1 complete. Graphs generated in $WORK_DIR"
    fi
fi

if [ "$MODE" = "distance" ] || [ "$MODE" = "all" ]; then
    if [ -n "${AFLGO:-}" ] && [ -f "$AFLGO/distance/gen_distance_fast.py" ]; then
        echo "[*] Calculating distances using AFLGo ($AFLGO)..."
        if [ -f "$WORK_DIR/BBcalls.txt" ]; then
            awk -F',' 'NF==2 && $1!="" && $2!=""' "$WORK_DIR/BBcalls.txt" > "$WORK_DIR/BBcalls.txt.clean" && mv "$WORK_DIR/BBcalls.txt.clean" "$WORK_DIR/BBcalls.txt"
        fi
        python3 "$AFLGO/distance/gen_distance_fast.py" "$SRC_DIR" "$WORK_DIR" ffmpeg_g
        echo "[*] Distance calculation complete: $WORK_DIR/distance.cfg.txt"
    elif [ -n "${FF_AFL:-}" ] && [ -f "$FF_AFL/scripts/gen_initial_distance.py" ]; then
        echo "[*] Calculating distances using FishFuzz ($FF_AFL)..."
        python3 "$FF_AFL/scripts/gen_initial_distance.py" "$WORK_DIR" || true
    elif [ -n "${WINDRANGER:-}" ]; then
        echo "[*] Processing Deviation Basic Blocks with WindRanger ($WINDRANGER)..."
        if [ -f "$SRC_DIR/ffmpeg_g.0.0.preopt.bc" ]; then
            cbi --targets="$WORK_DIR/BBtargets.txt" "$SRC_DIR/ffmpeg_g.0.0.preopt.bc" || true
            cp distance.txt condition_info.txt targets.txt "$OUT_DIR/" 2>/dev/null || true
            cp distance.txt condition_info.txt targets.txt "$WORK_DIR/" 2>/dev/null || true
        fi
    fi
fi

if [ "$MODE" = "pass2" ] || [ "$MODE" = "all" ]; then
    echo "[*] Starting Pass 2: Final Binary Instrumentation with ASan..."
    
    cd "$SRC_DIR"
    make clean || true
    make distclean || true
    find . -name "config.cache" -delete 2>/dev/null || true

    unset CFLAGS CXXFLAGS LDFLAGS
    export ASAN_OPTIONS="abort_on_error=1:detect_leaks=0:use_sigaltstack=0"

    if [ -n "${AFLGO:-}" ]; then
        DISTANCE_FILE="$WORK_DIR/distance.cfg.txt"
        if [ ! -f "$DISTANCE_FILE" ]; then
            touch "$DISTANCE_FILE"
        fi
        PASS2_CFLAGS="-distance=$DISTANCE_FILE -fsanitize=address"
    elif [ -n "${FF_AFL:-}" ]; then
        PASS2_CFLAGS="-pmode=origin -fsanitize=address"
    else
        PASS2_CFLAGS="-fsanitize=address"
    fi
    PASS2_LDFLAGS="-fsanitize=address"

    ./configure --cc="$CC" --cxx="$CXX" \
                --host-cc="clang" \
                --extra-cflags="$PASS2_CFLAGS" \
                --extra-ldflags="$PASS2_LDFLAGS" \
                --disable-shared --enable-static \
                --disable-x86asm \
                --disable-doc --disable-programs --enable-ffmpeg \
                --disable-everything --enable-decoder=rasc \
                --enable-demuxer=avi --enable-protocol=file

    make -j"$(nproc)"

    cp "$SRC_DIR/ffmpeg_g" "$OUT_DIR/ffmpeg_rasc"
    echo "[+] Successfully built instrumented binary: $OUT_DIR/ffmpeg_rasc"
fi
