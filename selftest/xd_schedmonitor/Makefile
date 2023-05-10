TESTAPP = testsched

.PHONY: app
app: $(TESTAPP)

.PHONY: clean
clean:
	$(Q)rm -rf $(TESTAPP) *.o

# Build final application
$(TESTAPP): %: %.o
	$(CC) $(CFLAGS) $^ $(LINK_OBJ) -o $@
	 @echo $@ "compiling completed."


# Build user-space code
%.o: %.c $(wildcard %.h)
	$(CC) $(CFLAGS) $(INCLUDES) -c $(filter %.c,$^) -o $@	

