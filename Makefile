all:
	cd randomx && $(MAKE) && $(MAKE) test
	cd xmss-alt && $(MAKE)
	cd src && $(MAKE)
clean:
	cd src && $(MAKE) clean
	cd xmss-alt && $(MAKE) clean
	cd randomx && $(MAKE) clean
push:
	git add . && git commit -S && cat ~/kmnyoshie | \
		termux-clipboard-set && git push
