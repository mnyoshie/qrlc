all:
	cd xmss-alt && $(MAKE)
	cd src && $(MAKE)
clean:
	cd src && $(MAKE) clean
	cd xmss-alt && $(MAKE) clean
