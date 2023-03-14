include ../../common/mk/var.mk

INCLUDES := -I$(INC_ROOT)

APPS = xd_ntrace

.PHONY: app
app: $(APPS)

.PHONY: clean
clean:
	$(Q)rm -rf $(APPS) *.skel.h *.o

# Build final application
$(APPS): %: %.o
	$(CC) $(CFLAGS) $^ $(LINK_OBJ) -o $@
	 @echo $@ "compiling completed."

$(patsubst %,%.o,$(APPS)): %.o: %.skel.h

.PHONY: install
install:
	install $(APPS) $(DESTDIR)

# Build user-space code
%.o: %.c $(wildcard %.h)
	$(CC) $(CFLAGS) $(INCLUDES) -c $(filter %.c,$^) -o $@	

%.o: %.cpp $(wildcard %.h)
	$(CXX) $(CXXFLAGS) $(INCLUDES) -c $(filter %.cpp,$^) -o $@

# Generate BPF skeletons
%.skel.h: %.bpf.o
	$(BPFTOOL) gen skeleton $< > $@

# Build BPF code
%.bpf.o: %.bpf.c
	$(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) $(BPF_NO_PRESERVE_ACCESS_INDEX)\
		     $(INCLUDES) -c $(filter %.c,$^) -o $@
	$(LLVM_STRIP) -g $@
