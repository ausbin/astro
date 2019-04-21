#!/bin/bash

set -e -o pipefail

install_dir=$(readlink -f "$(pwd)/submods/install-path")

git submodule update --init

printf 'Building unicorn...\n\n'
pushd submods/unicorn
    UNICORN_ARCHS=x86 ./make.sh
    PREFIX=$install_dir ./make.sh install
popd

printf 'Building elfutils...\n\n'
pushd submods/elfutils
    autoreconf -i -f
    ./configure --enable-maintainer-mode --prefix "$install_dir"
    make
    make install
popd
