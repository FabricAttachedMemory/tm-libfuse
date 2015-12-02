## Process this file with automake to produce Makefile.in

AM_CPPFLAGS = -I$(top_srcdir)/include -D_FILE_OFFSET_BITS=64 -D_REENTRANT
noinst_HEADERS = fioc.h
noinst_PROGRAMS = tmfsxmp tmfsxmp_fh null hello hello_ll fioc fioclient \
		  fsel fselclient tmcdxmp

LDADD = ../lib/libtmfs.la
tmfsxmp_fh_LDADD = ../lib/libtmfs.la ../lib/libulockmgr.la

fioclient_CPPFLAGS =
fioclient_LDFLAGS =
fioclient_LDADD =
fselclient_CPPFLAGS =
fselclient_LDFLAGS =
fselclient_LDADD =

