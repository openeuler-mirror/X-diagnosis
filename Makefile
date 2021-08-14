.PHONY: all clean check install

PREFIX=/usr
SBINDIR=$(DESTDIR)$(PREFIX)/sbin
VERSION = 0.1
CURDIR=$(shell pwd)

all: X-diagnosis

X-diagnosis:
	cd ${CURDIR}/src/oom_debug_info && make

clean:
	cd ${CURDIR}/src/oom_debug_info && make clean

install: all
	@echo "BEGIN INSTALL X-diagnosis..."
	install -m 500 ${CURDIR}/src/cpu/cpuload.py $(SBINDIR)/cpuload
	install -m 500 ${CURDIR}/src/memory/memtool.sh $(SBINDIR)/memtool
	@echo "END INSTALL X-diagnosis"

rpm:
	cd .. && tar -zcvf v$(VERSION).tar.gz X-diagnosis
	mkdir -p ~/rpmbuild/{BUILD,RPMS,SOURCES,SPECS,SRPMS}
	mv ../v$(VERSION).tar.gz ~/rpmbuild/SOURCES
	rpmbuild -ba misc/X-diagnosis.spec

check:
	# cd ${CURDIR}/tests && sh run_tests.sh
