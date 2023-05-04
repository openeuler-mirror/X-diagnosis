#!/bin/bash
PRJ_DIR=$(dirname $(readlink -f "$0"))
PAHOLE=/usr/bin/pahole
BPFTOOL=/usr/sbin/bpftool
SRC_DIR=${PRJ_DIR}/../src/ebpf
VMLINUX_DIR=${SRC_DIR}/common/include
VMLINUX_H=${VMLINUX_DIR}/vmlinux.h
KN_HEAD_DIR=${SRC_DIR}/../python/xdiagnose/cmdfile/kernel
DEBUGVERSION=""
VMLINUX=""

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
	rm -rf ./build_ebpf
}

function check_env()
{
	[ ! -f $BPFTOOL ] && {
		echo "bpftool is not install, please install it first"
		exit 1
	}

	[ ! -f $BPFTOOL ] && {
		echo "pahole is not install, please install dwarves first"
		exit 1
	}

	kernel_debuginfo=`rpm -q kernel-debuginfo`
	[ $? != 0 ] && {
		echo "kernel-debuginfo is not install, please install it first"
		exit 1
	}
	
	DEBUGVERSION=`rpm -q --qf '%{version}-%{release}.%{arch}' kernel-debuginfo`
	VMLINUX="/usr/lib/debug/lib/modules/$DEBUGVERSION/vmlinux"
	[ ! -f ${VMLINUX} ] && {
		echo "${VMLINUX} is not exist"
		exit 1
	}
}

function gen_vmlinux_h()
{
	[ ! -f ${VMLINUX_H} ]&& {
		echo "go to generate vmlinux.h"
		[ ! -d ${VMLINUX_DIR} ]&& {
			mkdir -p ${VMLINUX_DIR}
		}

		cp ${VMLINUX} vmlinux_tmp
		bpf_support=`objdump -h vmlinux_tmp |grep '\.BTF'`
		[ "f${bpf_support}" == "f" ] && {
			pahole -J vmlinux_tmp
		}
		bpftool btf dump file vmlinux_tmp format c > ${VMLINUX_H}
		[ $? != 0 ] && {
			echo "generate vmlinux.h failed, ${VMLINUX} is not supported"
			rm -rf vmlinux_tmp ${VMLINUX_H}
			exit 1
		}
		rm -rf vmlinux_tmp
	}

	mkdir -p ${KN_HEAD_DIR}
	[ ! -f ${KN_HEAD_DIR}/${DEBUGVERSION}.f ]&& {
		echo ${VMLINUX}
		echo ${KN_HEAD_DIR}/${DEBUGVERSION}.f
		gdb --batch --ex "info functions" ${VMLINUX} > ${KN_HEAD_DIR}/${DEBUGVERSION}.f
	}

        [ ! -f ${KN_HEAD_DIR}/${DEBUGVERSION}.h ]&& {
		pahole ${VMLINUX} > ${KN_HEAD_DIR}/${DEBUGVERSION}.h 
	}
}

function build()
{
	check_env
	gen_vmlinux_h

	echo "start compile"
	cd ${SRC_DIR}
	cmake . -DXD_INSTALL_BINDIR=$1 -B build_ebpf
	cd build_ebpf
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
	INTALL_DIR=$2
	[ -z $2 ] && {
		INTALL_DIR=/usr/bin/xdiag/ebpf
		mkdir -p ${INTALL_DIR}
	}

	build ${INTALL_DIR}
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
