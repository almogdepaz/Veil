#!/bin/bash
# Run all examples with specified backend
# Usage: ./run_examples.sh [risc0|sp1|mock]

set -e

BACKEND="${1:-risc0}"

case "$BACKEND" in
    risc0|sp1|mock)
        ;;
    *)
        echo "usage: $0 [risc0|sp1|mock]"
        exit 1
        ;;
esac

echo "=== running examples with $BACKEND backend ==="
echo

EXAMPLES=$(ls examples/*.rs | xargs -n1 basename | sed 's/\.rs$//')

for example in $EXAMPLES; do
    # skip examples that require specific backends
    if [ "$BACKEND" = "mock" ] && [ "$example" = "benchmark_aggregation" ]; then
        echo "--- $example --- (skipped: requires risc0/sp1)"
        continue
    fi
    if [ "$BACKEND" = "mock" ] && [ "$example" = "recursive_aggregation" ]; then
        echo "--- $example --- (skipped: requires risc0/sp1)"
        continue
    fi
    if [ "$BACKEND" = "mock" ] && [ "$example" = "generate_proof_database" ]; then
        echo "--- $example --- (skipped: requires risc0/sp1)"
        continue
    fi

    echo "--- $example ---"
    cargo run-$BACKEND --example "$example" || {
        echo "FAILED: $example"
        exit 1
    }
    echo
done

echo "=== all examples completed ==="
