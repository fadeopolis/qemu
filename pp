#!/bin/bash

#simple driver to run program_profiler cpp plugin
# QEMU must have been built in current folder
#example: ./pp x86_64 ~/out true

set -uo pipefail

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

handler()
{
    info "sending SIGTERM to qemu..."
    kill -s SIGTERM $qemu_pid
    wait $qemu_pid
    qemu_status=$?
}

driver()
{
    [ $# -lt 3 ] && die "usage: architecture[:sysroot] output_dir program [program_args]"

    architecture="$1"
    sysroot=$(echo "$architecture" | cut -f 2 -d ':')
    architecture=$(echo "$architecture" | cut -f 1 -d ':')
    [ "$architecture" == "$sysroot" ] && sysroot=""
    [ "$sysroot" != "" ] && sysroot="-L $sysroot"
    shift
    output_dir="$1"
    shift
    program="$1"
    shift

    rustfilt_bin=$(which rustfilt)
    [ -z "$rustfilt_bin" ] && rustfilt_bin=cat
    cppfilt_bin=$(which c++filt)
    [ -z "$cppfilt_bin" ] && cppfilt_bin=cat

    which_program=$(which "$program")
    if [ "$which_program" != "" ]
    then
        program="$which_program"
    fi

    export TPI_OUTPUT="/tmp/$$-out.json"
    export PLUGIN_CPP="program_profiler"
    qemu_bin="$script_directory/$architecture-linux-user/qemu-$architecture"
    python_script="$script_directory/tcg/plugins/cpp/program_profiler/gen_files_from_json.py"

    "$qemu_bin" $sysroot -tcg-plugin cpp "$program" "$@" <&0 &
    qemu_pid=$!
    trap handler SIGINT
    wait $qemu_pid
    qemu_status=$?
    # check status, 130 is for CTRL-C
    [ $qemu_status -ne 0 -a $qemu_status -ne 130 ] &&\
        die "QEMU failed: returned $qemu_status"
    trap - SIGINT

    info "json created is $TPI_OUTPUT ($(du -h $(readlink -f $TPI_OUTPUT) | cut -f 1))"

    [ ! -z "${PP_STOP_AFTER_RUN:-}" ] && exit 0

    info "pp: filter c++ and rust symbols in $TPI_OUTPUT"
    out_file="$TPI_OUTPUT".filtered
    cat "$TPI_OUTPUT" | "$rustfilt_bin" | "$cppfilt_bin" > $out_file
    info "final json file used is: $out_file"
    "$python_script" -i "$out_file" -o "$output_dir" || die "python script failed"

    echo "output is available at $output_dir/index.html"
}

driver "$@"
