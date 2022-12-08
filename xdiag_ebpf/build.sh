#!/bin/bash
PRJ_DIR=$(dirname $(readlink -f "$0"))

TOOLS_DIR=${PRJ_DIR}/tools
SRC_DIR=${PRJ_DIR}/src
VMLINUX_DIR=${SRC_DIR}/include
VMLINUX_H=${VMLINUX_DIR}/vmlinux.h

function print_help()
{
	echo "Usage: $0 OPERATOR OPTIONS"
    echo "OPERATOR: "
	echo "	-i build and install"
	echo "	-b build"
	echo "	-c clean"

}

function clean()
{
    cd ${SRC_DIR}
    make clean
}

function build()
{
	cd ${TOOLS_DIR}
	ARCH=$(uname -m)
	[ ! -f "bpftool" ] && {
		ln -s bpftool_${ARCH} bpftool
	}

	[ ! -f ${VMLINUX_H} ]&& {
		echo "go to gen vmlinux.h"
		./bpftool btf dump file ${1:-/sys/kernel/btf/vmlinux} format c > ${VMLINUX_H}
	}
	echo ${SRC_DIR}
	cd ${SRC_DIR}
	echo "start compile"
	make
}

function install()                                                     
{
    cd ${SRC_DIR}
    export DESTDIR=$1
    make install
}

[ "$1" == "-c" ] && {
	clean
	exit  0
}
[ "$1" == "-b" ] && {
	build
	exit  0
}
[ "$1" == "-i" ] && {
    INTALL_DIR=$2
    [ -z $2 ] && {
        INTALL_DIR=/usr/bin/xdiag/ebpf
        mkdir -p ${INTALL_DIR}
    }
	install ${INTALL_DIR}
	exit  0
}

if [ -z $1 ] || [ $1 == "-h" ]
	then
		print_help
		exit 0
fi
