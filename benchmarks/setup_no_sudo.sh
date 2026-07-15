#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
VENV="${PROJECT_ROOT}/.venv"
SOURCE="${VENV}/liboqs-src"
BUILD="${VENV}/liboqs-build-noopenssl"
INSTALL="${VENV}/liboqs"

cd "${PROJECT_ROOT}"

python3 -m venv "${VENV}"
"${VENV}/bin/python" -m pip install --upgrade pip
"${VENV}/bin/python" -m pip install -r benchmarks/requirements.txt

if [[ ! -d "${SOURCE}/.git" ]]; then
    git clone --depth 1 https://github.com/open-quantum-safe/liboqs.git "${SOURCE}"
fi

"${VENV}/bin/cmake" \
    -S "${SOURCE}" \
    -B "${BUILD}" \
    -GNinja \
    -DCMAKE_MAKE_PROGRAM="${VENV}/bin/ninja" \
    -DCMAKE_C_COMPILER=/usr/bin/gcc \
    -DCMAKE_ASM_COMPILER=/usr/bin/gcc \
    -DBUILD_SHARED_LIBS=ON \
    -DOQS_BUILD_ONLY_LIB=ON \
    -DOQS_ALGS_ENABLED=STD \
    -DOQS_USE_OPENSSL=OFF \
    -DCMAKE_INSTALL_PREFIX="${INSTALL}"

"${VENV}/bin/cmake" --build "${BUILD}" --parallel 4
"${VENV}/bin/cmake" --build "${BUILD}" --target install

echo "liboqs installed at ${INSTALL}"
echo "Run: .venv/bin/python benchmarks/slh_dsa_benchmark.py --iterations 3"
