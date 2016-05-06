SUBDIRS = . include src doc test
EXTRA_DIST = CHANGELOG.md README.md LICENSE

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = cjose.pc

doxygen:
	cd doc && $(MAKE) doxygen

test : check
	cat test/check_cjose.log
