#!/bin/bash

set -eu

current_dir=$(pwd)
export PATH="$PATH:${current_dir}/dist/vdexExtractor/bin:${current_dir}/dist/jadx/bin"
export PYTHONPATH="${current_dir}/src"

python -m test_teezz