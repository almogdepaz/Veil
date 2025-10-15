#!/bin/bash
set -e

# colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # no color

echo -e "${BLUE}clvm-zk backend benchmark runner${NC}"
echo "====================================="
echo


TESTED_BACKENDS=()
FAILED_BACKENDS=()


RISC0_AVAILABLE=false
if [ -f "./install-deps.sh" ]; then
    if command -v cargo-risczero &> /dev/null || rustup target list --installed | grep -q riscv32im-unknown-none-elf; then
        echo -e "${GREEN}✓${NC} risc0 dependencies available"
        RISC0_AVAILABLE=true
    else
        echo -e "${YELLOW}⚠${NC} risc0 target not installed - run ./install-deps.sh"
    fi
else
    echo -e "${YELLOW}⚠${NC} install-deps.sh not found"
fi


SP1_AVAILABLE=false
if command -v cargo-prove &> /dev/null; then
    echo -e "${GREEN}✓${NC} sp1 toolchain available"
    SP1_AVAILABLE=true
else
    echo -e "${YELLOW}⚠${NC} sp1 toolchain not available - run 'curl -L https://sp1.succinct.xyz | bash && sp1up'"
fi

# check if docker is available for plonk/groth16 modes
DOCKER_AVAILABLE=false
if command -v docker &> /dev/null; then
    if docker info &> /dev/null 2>&1; then
        echo -e "${GREEN}✓${NC} docker available (plonk/groth16 modes supported)"
        DOCKER_AVAILABLE=true
    else
        echo -e "${YELLOW}⚠${NC} docker installed but not running - plonk/groth16 modes will be skipped"
        echo "    start docker: 'open -a Docker' (macOS) or 'sudo systemctl start docker' (linux)"
    fi
else
    echo -e "${YELLOW}⚠${NC} docker not installed - plonk/groth16 modes will be skipped"
    echo "    install docker: './install-deps.sh -d'"
fi

echo

# test risc0 backend
if [ "$RISC0_AVAILABLE" = true ]; then
    echo -e "${BLUE}━━━ testing risc0 backend ━━━${NC}"
    if cargo run --example backend_benchmark --features risc0 --no-default-features --release 2>&1; then
        TESTED_BACKENDS+=("risc0")
        echo -e "${GREEN}✓ risc0 test passed${NC}"
    else
        FAILED_BACKENDS+=("risc0")
        echo -e "${RED}✗ risc0 test failed${NC}"
    fi
    echo
else
    echo -e "${YELLOW}skipping risc0 (not available)${NC}"
    echo
fi

# test sp1 backend in all modes
if [ "$SP1_AVAILABLE" = true ]; then
    for MODE in core compressed; do
        echo -e "${BLUE}━━━ testing sp1 backend ($MODE mode) ━━━${NC}"
        if SP1_PROOF_MODE=$MODE cargo run --example backend_benchmark --features sp1 --no-default-features --release 2>&1; then
            TESTED_BACKENDS+=("sp1-$MODE")
            echo -e "${GREEN}✓ sp1 $MODE test passed${NC}"
        else
            FAILED_BACKENDS+=("sp1-$MODE")
            echo -e "${RED}✗ sp1 $MODE test failed${NC}"
        fi
        echo
    done

    # test docker-based modes
    if [ "$DOCKER_AVAILABLE" = true ]; then
        for MODE in plonk groth16; do
            echo -e "${BLUE}━━━ testing sp1 backend ($MODE mode) ━━━${NC}"
            if SP1_PROOF_MODE=$MODE cargo run --example backend_benchmark --features sp1 --no-default-features --release 2>&1; then
                TESTED_BACKENDS+=("sp1-$MODE")
                echo -e "${GREEN}✓ sp1 $MODE test passed${NC}"
            else
                FAILED_BACKENDS+=("sp1-$MODE")
                echo -e "${RED}✗ sp1 $MODE test failed${NC}"
            fi
            echo
        done
    else
        echo -e "${YELLOW}skipping sp1 plonk/groth16 modes (docker required)${NC}"
        echo
    fi
else
    echo -e "${YELLOW}skipping sp1 (not available)${NC}"
    echo
fi


echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo -e "${BLUE}benchmark summary${NC}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo -e "tested backends: ${#TESTED_BACKENDS[@]}"
echo -e "failed backends: ${#FAILED_BACKENDS[@]}"

if [ ${#TESTED_BACKENDS[@]} -gt 0 ]; then
    echo -e "\n${GREEN}passed:${NC}"
    for backend in "${TESTED_BACKENDS[@]}"; do
        echo "  ✓ $backend"
    done
fi

if [ ${#FAILED_BACKENDS[@]} -gt 0 ]; then
    echo -e "\n${RED}failed:${NC}"
    for backend in "${FAILED_BACKENDS[@]}"; do
        echo "  ✗ $backend"
    done
    exit 1
fi

echo -e "\n${GREEN}all benchmarks passed!${NC}"