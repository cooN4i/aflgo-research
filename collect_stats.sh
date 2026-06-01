INTERVAL=${1:-300}
OUT_DIR=${2:-/mnt/d/НИР/stats}

mkdir -p "$OUT_DIR"

while true; do
    TIMESTAMP="$(date +%Y%m%d_%H%M)"

    for FUZZER in mod master; do
        if [ "$FUZZER" = "mod" ]; then
            STAT_DIR="/mnt/d/НИР/aflgo-mod-runs/out/mod"
        else
            STAT_DIR="/mnt/d/НИР/aflgo-orig-runs/out/master"
        fi

        if [ -d "$STAT_DIR" ]; then
            cp "$STAT_DIR/fuzzer_stats"   "$OUT_DIR/${FUZZER}_${TIMESTAMP}_stats.txt" 2>/dev/null
            cp "$STAT_DIR/plot_data"      "$OUT_DIR/${FUZZER}_${TIMESTAMP}_plot_data.txt" 2>/dev/null
        fi
    done

    sleep "$INTERVAL"
done
