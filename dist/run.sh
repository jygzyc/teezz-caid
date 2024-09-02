#!/bin/bash

set -eu
DEVICE_ID=${2}
LIB_PATH=${1}

current_dir=$(pwd)
export PATH="$PATH:${current_dir}/dist/vdexExtractor/bin:${current_dir}/dist/jadx/bin"
export PYTHONPATH="${current_dir}/src"

python -m dep_finder -w inout --target_lib ${LIB_PATH} --device_id ${DEVICE_ID} -l ${current_dir}/log.ini