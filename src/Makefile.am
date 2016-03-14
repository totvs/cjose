AM_CFLAGS =-std=gnu99 --pedantic -Wall -Werror -g -O2 -I$(top_builddir)/include

lib_LTLIBRARIES=libcjose.la
libcjose_la_CPPFLAGS= -I$(topdir)/include
libcjose_la_SOURCES=version.c \
					base64.c \
                    jwk.c \
                    jwe.c \
                    jws.c \
                    header.c \
                    error.c
