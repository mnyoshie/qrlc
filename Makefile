all: config.mk
	cd randomx && $(MAKE) && $(MAKE) test
	cd cryptonight && $(MAKE) && $(MAKE) test
	cd src && $(MAKE)

config.mk:
	$(MAKE) -f configure.mk

clean:
	cd src && $(MAKE) clean
	cd cryptonight && $(MAKE) clean
	cd randomx && $(MAKE) clean
	rm tests/*.bin config.mk

push:
	git add . && git commit -S && cat ~/kmnyoshie | \
		termux-clipboard-set && git push $(f)
