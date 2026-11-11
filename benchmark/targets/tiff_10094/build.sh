#!/bin/bash
set -e

SRC_DIR="$1"
OUT_DIR="$2"
WORK_DIR="$3"
FUZZER="${4:-aflgo}"

if [ -z "$SRC_DIR" ] || [ -z "$OUT_DIR" ] || [ -z "$WORK_DIR" ]; then
    echo "Usage: $0 <src_dir> <out_dir> <work_dir> [fuzzer]"
    exit 1
fi

mkdir -p "$OUT_DIR" "$WORK_DIR"

# Ensure /fuzzer is executable
chmod -R +x /fuzzer 2>/dev/null || true

# Target basic block for CVE-2016-10094 in tiff2ps.c:2543 (PSDataPalette)
cat << 'EOF' > "$WORK_DIR/BBtargets.txt"
tiff2ps.c:2543
tiff2ps.c:2544
tiff2ps.c:2558
EOF

export ASAN_OPTIONS="abort_on_error=1:detect_leaks=0:use_sigaltstack=0"

case "$FUZZER" in
    "aflgo_mod"|"aflgo")
        echo "Building tiff_10094 for AFLGo/AFLGo_mod..."
        
        # Step 1: LLVM Pass to extract CFG and basic block info
        export AFLGO="/fuzzer/aflgo-mod"
        export AFL_PATH="/fuzzer/aflgo-mod/instrument"
        export PATH="/usr/lib/llvm-11/bin:$AFL_PATH:$PATH"
        export CC=afl-clang-fast
        export CXX=afl-clang-fast++
        
        export ADDITIONAL="-targets=$WORK_DIR/BBtargets.txt -outdir=$WORK_DIR -flto -fuse-ld=gold -Wl,-plugin-opt=save-temps"
        export CFLAGS="-g -Wno-error $ADDITIONAL"
        export CXXFLAGS="-g -Wno-error $ADDITIONAL"
        
        cd "$SRC_DIR"
        ./autogen.sh || true
        ./configure --disable-shared --prefix="$WORK_DIR/install"
        make -C port clean || true
        make -C libtiff clean || true
        make -C tools clean || true
        make -C port -j$(nproc)
        make -C libtiff -j$(nproc)
        make -C tools tiff2ps -j$(nproc)
        
        # Clean BBcalls.txt if present
        if [ -f "$WORK_DIR/BBcalls.txt" ]; then
            awk -F',' 'NF==2 && $1!="" && $2!=""' "$WORK_DIR/BBcalls.txt" > "$WORK_DIR/BBcalls.txt.clean" && mv "$WORK_DIR/BBcalls.txt.clean" "$WORK_DIR/BBcalls.txt"
        fi
        
        # Step 2: Compute distances
        python3 /fuzzer/aflgo-mod/distance/gen_distance_fast.py "$SRC_DIR/tools" "$WORK_DIR" tiff2ps
        
        # Step 3: Compile with distance instrumentation and ASan
        make clean || true
        make distclean || true
        export CFLAGS="-g -fsanitize=address -Wno-error -distance=$WORK_DIR/distance.cfg.txt"
        export CXXFLAGS="-g -fsanitize=address -Wno-error -distance=$WORK_DIR/distance.cfg.txt"
        
        ./autogen.sh || true
        ./configure --disable-shared --prefix="$WORK_DIR/install"
        make -C port -j$(nproc)
        make -C libtiff -j$(nproc)
        make -C tools tiff2ps -j$(nproc)
        
        cp "$SRC_DIR/tools/tiff2ps" "$OUT_DIR/tiff_10094"
        echo "Successfully built tiff_10094 for AFLGo/AFLGo_mod"
        ;;
        
    "aflpp"|"aflplusplus")
        echo "Building tiff_10094 for AFL++..."
        export CC=afl-clang-fast
        export CXX=afl-clang-fast++
        export CFLAGS="-g -fsanitize=address -Wno-error"
        export CXXFLAGS="-g -fsanitize=address -Wno-error"
        
        cd "$SRC_DIR"
        ./autogen.sh || true
        ./configure --disable-shared --prefix="$WORK_DIR/install"
        make -C port -j$(nproc)
        make -C libtiff -j$(nproc)
        make -C tools tiff2ps -j$(nproc)
        
        cp "$SRC_DIR/tools/tiff2ps" "$OUT_DIR/tiff_10094"
        echo "Successfully built tiff_10094 for AFL++"
        ;;
        
    "beacon")
        echo "Building tiff_10094 for Beacon..."
        export CC=/fuzzer/beacon/Test/clang
        export CXX=/fuzzer/beacon/Test/clang++
        export CFLAGS="-g -fsanitize=address -Wno-error"
        export CXXFLAGS="-g -fsanitize=address -Wno-error"
        
        cd "$SRC_DIR"
        ./autogen.sh || true
        ./configure --disable-shared --prefix="$WORK_DIR/install"
        make -C port -j$(nproc)
        make -C libtiff -j$(nproc)
        make -C tools tiff2ps -j$(nproc)
        
        cp "$SRC_DIR/tools/tiff2ps" "$OUT_DIR/tiff_10094"
        echo "Successfully built tiff_10094 for Beacon"
        ;;
        
    *)
        echo "Building tiff_10094 with generic/ASan..."
        export CC=clang
        export CXX=clang++
        export CFLAGS="-g -fsanitize=address -Wno-error"
        export CXXFLAGS="-g -fsanitize=address -Wno-error"
        
        cd "$SRC_DIR"
        ./autogen.sh || true
        ./configure --disable-shared --prefix="$WORK_DIR/install"
        make -C port -j$(nproc)
        make -C libtiff -j$(nproc)
        make -C tools tiff2ps -j$(nproc)
        
        cp "$SRC_DIR/tools/tiff2ps" "$OUT_DIR/tiff_10094"
        echo "Successfully built tiff_10094"
        ;;
esac

