SUBDIRS = . include src doc test

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = cjose.pc

doxygen:
	cd doc && $(MAKE) doxygen

test : check
	cat test/check_cjose.log
