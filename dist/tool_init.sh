#!/bin/bash

tools_dir="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
jadx_dir="$tools_dir/jadx"
if [ ! -d $jadx_dir ]; then
    mkdir -p $jadx_dir
    pushd $jadx_dir

    json=$(curl -s https://api.github.com/repos/skylot/jadx/releases/latest)
    tag_name=$(echo "$json" | grep '"tag_name":' | cut -d '"' -f 4 | sed 's/^v//')
    echo $tag_name
    wget "https://github.com/skylot/jadx/releases/download/v${tag_name}/jadx-${tag_name}.zip"

    ZIP_FILE="jadx-${tag_name}.zip"
    unzip -o "$ZIP_FILE"
    rm $ZIP_FILE
    popd
else
    echo "$jadx_dir already exists"
fi

vdexExtractor_dir="$tools_dir/vdexExtractor"
if [ -d $vdexExtractor_dir ]; then
    pushd $vdexExtractor_dir
    ./make.sh clean
    make CFLAGS="${CFLAGS} -Wno-error=vla-parameter" -C src
    popd
else
    echo "$vdexExtractor_dir not exists"
    git clone https://github.com/anestisb/vdexExtractor.git $vdexExtractor_dir
    pushd $vdexExtractor_dir
    ./make.sh clean
    make CFLAGS="${CFLAGS} -Wno-error=vla-parameter" -C src
    popd
fi

sudo apt-get install graphviz