#!/usr/bin/env bash
# ==============================================================================
# Build script for Target 3: VP9 Decoder
# Supports two-pass instrumentation for Directed Fuzzers
# ==============================================================================
set -euo pipefail

MODE="${1:-all}"
SRC_DIR="${SRC_DIR:-/src/ffmpeg}"
OUT_DIR="${OUT_DIR:-/out}"
WORK_DIR="${WORK_DIR:-/work}"

export CC="${CC:-afl-clang-fast}"
export CXX="${CXX:-afl-clang-fast++}"

mkdir -p "$OUT_DIR" "$WORK_DIR"

cd "$SRC_DIR"

# Set target lines for Directed Fuzzers
echo "vp9.c:1340" > "$WORK_DIR/BBtargets.txt"

if [ "$MODE" = "pass1" ] || [ "$MODE" = "all" ]; then
    echo "[*] Starting Pass 1: CFG / CallGraph Extraction for VP9..."
    
    make clean || true
    make distclean || true

    export ADDITIONAL="-targets=$WORK_DIR/BBtargets.txt -outdir=$WORK_DIR -flto -fuse-ld=gold -Wl,-plugin-opt=save-temps"
    export CFLAGS="${CFLAGS:-} $ADDITIONAL"
    export CXXFLAGS="${CXXFLAGS:-} $ADDITIONAL"

    ./configure --cc="$CC" --cxx="$CXX" \
                --disable-shared --enable-static \
                --disable-doc --disable-programs --enable-ffmpeg \
                --disable-everything --enable-decoder=vp9 \
                --enable-demuxer=ivf,matroska --enable-protocol=file

    make -j"$(nproc)"
    
    echo "[*] Pass 1 complete. Graphs generated in $WORK_DIR"
fi

if [ "$MODE" = "distance" ] || [ "$MODE" = "all" ]; then
    if [ -n "${AFLGO:-}" ] && [ -f "$AFLGO/distance/gen_distance_fast.py" ]; then
        echo "[*] Calculating distances using AFLGo ($AFLGO)..."
        python3 "$AFLGO/distance/gen_distance_fast.py" "$SRC_DIR" "$WORK_DIR" ffmpeg_g
        echo "[*] Distance calculation complete: $WORK_DIR/distance.cfg.txt"
    elif [ -n "${FF_AFL:-}" ] && [ -f "$FF_AFL/scripts/gen_initial_distance.py" ]; then
        echo "[*] Calculating distances using FishFuzz ($FF_AFL)..."
        python3 "$FF_AFL/scripts/gen_initial_distance.py" -t "$WORK_DIR" || true
    elif [ -n "${WINDRANGER:-}" ]; then
        echo "[*] Processing Deviation Basic Blocks with WindRanger ($WINDRANGER)..."
        if [ -f "$SRC_DIR/ffmpeg_g.0.0.preopt.bc" ]; then
            cbi --targets="$WORK_DIR/BBtargets.txt" "$SRC_DIR/ffmpeg_g.0.0.preopt.bc" || true
        fi
    fi
fi

if [ "$MODE" = "pass2" ] || [ "$MODE" = "all" ]; then
    echo "[*] Starting Pass 2: Final Binary Instrumentation with ASan..."
    
    cd "$SRC_DIR"
    make clean || true

    DISTANCE_FILE="$WORK_DIR/distance.cfg.txt"
    if [ ! -f "$DISTANCE_FILE" ]; then
        touch "$DISTANCE_FILE"
    fi

    export CFLAGS="${CFLAGS:-} -distance=$DISTANCE_FILE -fsanitize=address"
    export CXXFLAGS="${CXXFLAGS:-} -distance=$DISTANCE_FILE -fsanitize=address"
    export LDFLAGS="${LDFLAGS:-} -fsanitize=address"

    ./configure --cc="$CC" --cxx="$CXX" \
                --disable-shared --enable-static \
                --disable-doc --disable-programs --enable-ffmpeg \
                --disable-everything --enable-decoder=vp9 \
                --enable-demuxer=ivf,matroska --enable-protocol=file

    make -j"$(nproc)"

    cp "$SRC_DIR/ffmpeg_g" "$OUT_DIR/vlc_vp9"
    echo "[+] Successfully built instrumented binary: $OUT_DIR/vlc_vp9"
fi
