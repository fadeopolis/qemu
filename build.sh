#!/bin/bash
#git clean -ffdx && ./configure --enable-tcg-plugin-cpp --target-list=x86_64-linux-user --cc='ccache gcc' --cxx='ccache g++'
mkdir -p build && bear -a -o build/compile_commands.json make -j$(cat /proc/cpuinfo | grep processor | wc -l) "$@"
