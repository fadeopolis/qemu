#!/bin/bash

#simple driver to run program_profiler cpp plugin
# QEMU must have been built in current folder
#example: ./pp x86_64 ~/out true

set -euo pipefail

script_directory=$(dirname $(readlink -f $0))

die()
{
    error "$@"
    exit 1
}

error()
{
    echo "ERROR: $@"
}

info()
{
    echo "INFO: $@"
}

driver()
{
    [ $# -lt 3 ] && die "usage: architecture output_dir program [program_args]"

    architecture="$1"
    shift
    output_dir="$1"
    shift
    program="$1"
    shift

    which_program=$(which "$program")
    if [ "$which_program" != "" ]
    then
        program="$which_program"
    fi

    export TPI_OUTPUT="/tmp/$$-out.json"
    export TCG_PLUGIN_CPP="program_profiler"
    qemu_bin="$script_directory/$architecture-linux-user/qemu-$architecture"
    python_script="$script_directory/tcg/plugins/cpp/program_profiler/gen_files_from_json.py"

    "$qemu_bin" -tcg-plugin cpp "$program" "$@" || die "running QEMU failed"
    "$python_script" -i "$TPI_OUTPUT" -o "$output_dir" || die "python script failed"

    echo "output is available at $output_dir/index.html"
}

driver "$@"
