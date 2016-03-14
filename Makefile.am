SUBDIRS = . include src test doc

doxygen:
	cd doc && $(MAKE) doxygen

test : check
	cat test/check_cjose.log
