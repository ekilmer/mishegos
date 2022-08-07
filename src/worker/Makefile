WORKERS = bfd \
	capstone \
	dynamorio \
	fadec \
	xed \
	zydis \
	bddisasm \
	iced \
	yaxpeax-x86 \
	ghidra

.PHONY: all
all: worker $(WORKERS)

worker: worker.c

.PHONY: $(WORKERS)
$(WORKERS):
	$(MAKE) \
		CFLAGS="$(CFLAGS) -fPIC" \
		LDFLAGS="-shared" \
		-C $@/

.PHONY: clean
clean:
	rm -rf worker
	for dir in $(WORKERS); do \
		$(MAKE) -C $$dir/ clean; \
	done
