#!/bin/bash

echo "clvm-zk backend benchmark runner"
echo "====================================="
echo

# check if risc0 is available
if [ -f "./install-deps.sh" ]; then
    echo "📦 risc0 dependencies available"
else
    echo "risc0 dependencies not available - run ./install-deps.sh"
fi

# check if sp1 is available  
if command -v cargo-prove &> /dev/null; then
    echo "📦 sp1 toolchain available"
else
    echo "sp1 toolchain not available - run 'curl -L https://sp1.succinct.xyz | bash && sp1up'"
fi

# check if docker is available for plonk/groth16 modes
if command -v docker &> /dev/null; then
    if docker info &> /dev/null; then
        echo "📦 docker available (plonk/groth16 modes supported)"
        DOCKER_AVAILABLE=true
    else
        echo "docker installed but not running - plonk/groth16 modes will be skipped"
        echo "    start docker: 'open -a Docker' (macOS) or 'sudo systemctl start docker' (linux)"
        DOCKER_AVAILABLE=false
    fi
else
    echo "docker not installed - plonk/groth16 modes will be skipped"
    echo "    install docker: './install-deps.sh -d'"
    DOCKER_AVAILABLE=false
fi

echo

# test risc0 backend
echo "testing risc0 backend..."
cargo run --example backend_benchmark --features risc0 --no-default-features --release || echo "risc0 test failed"

echo

# test sp1 backend in all modes
echo "testing sp1 backend (core mode)..."
SP1_PROOF_MODE=core cargo run --example backend_benchmark --features sp1 --no-default-features --release || echo "sp1 core test failed"

echo
echo "testing sp1 backend (compressed mode)..."  
SP1_PROOF_MODE=compressed cargo run --example backend_benchmark --features sp1 --no-default-features --release || echo "sp1 compressed test failed"

if [ "$DOCKER_AVAILABLE" = true ]; then
    echo
    echo "testing sp1 backend (plonk mode)..."
    SP1_PROOF_MODE=plonk cargo run --example backend_benchmark --features sp1 --no-default-features --release || echo "sp1 plonk test failed"

    echo
    echo "testing sp1 backend (groth16 mode)..."
    SP1_PROOF_MODE=groth16 cargo run --example backend_benchmark --features sp1 --no-default-features --release || echo "sp1 groth16 test failed"
else
    echo
    echo "skipping plonk and groth16 modes (docker required)"
fi

echo
echo "benchmark complete"