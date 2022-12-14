ROOT_DIR := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))
BPFTOOL ?= $(ROOT_DIR)/../../common/bpftools/bpftool
CLANG ?= clang                                      
LLVM_STRIP ?= llvm-strip
CXX = g++                                                        
CFLAGS := -g -Wall
CXXFLAGS := -g -Wall
CC = gcc
ARCH := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/' | sed 's/ppc64le/powerpc/' | sed 's/mips.*/mips/')

TARGET_DIR=/usr/bin/xdiag/ebpf
LINK_OBJ = -lpthread -lbpf -lelf -lz

INC_ROOT := -I/usr/include \
	    -I$(ROOT_DIR)/../../common/include \
	    -I$(ROOT_DIR)/../../common/bpf_common
