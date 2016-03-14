## Primary check for Doxygen support
if DX_COND_doc

TAGFILE = @PACKAGE@-@VERSION@.tag

## HTML-specific configuration
if DX_COND_html

DX_INSTALL_HTML = html
DX_FILES_HTML = $(shell find html -type f)
DX_CLEAN_HTML = $(DX_FILES_HTML) html

endif DX_COND_html

## LATEX-specific configuration
if DX_COND_latex

DX_INSTALL_LATEX = latex
DX_FILES_LATEX = $(shell find latex -type f)
DX_CLEAN_LATEX = $(DX_FILES_LATEX) latex

endif DX_COND_latex

## General instructions

doxygendir = $(datadir)/docs

nobase_doxygen_DATA = $(DX_FILES_HTML) $(DX_FILES_LATEX)

$(TAGFILE): $(top_builddir)/include
	$(DX_ENV) $(DX_DOXYGEN) $(DX_CONFIG)
	echo "$(shell date -ju)" > $(TAGFILE)

doxygen: clean-local $(TAGFILE)

install-data-local: $(TAGFILE)

clean-local:
	rm -rf	$(TAGFILE) $(DX_CLEAN_HTML) $(DX_CLEAN_LATEX)

.PHONY: doxygen

endif DX_COND_doc
