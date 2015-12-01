## Process this file with automake to produce Makefile.in

AM_CPPFLAGS = -I$(top_srcdir)/include -DTMFSRMOUNT_DIR=\"$(bindir)\" \
 -D_FILE_OFFSET_BITS=64 -D_REENTRANT -DTMFS_USE_VERSION=26

lib_LTLIBRARIES = libtmfs.la libulockmgr.la

if BSD
mount_source = mount_bsd.c
else
mount_source = mount.c mount_util.c mount_util.h
endif

if ICONV
iconv_source = modules/iconv.c
else
iconv_source =
endif

libtmfs_la_SOURCES = 		\
	tmfs.c			\
	tmfs_i.h		\
	tmfs_kern_chan.c	\
	tmfs_loop.c		\
	tmfs_loop_mt.c		\
	tmfs_lowlevel.c		\
	tmfs_misc.h		\
	tmfs_mt.c		\
	tmfs_opt.c		\
	tmfs_session.c		\
	tmfs_signals.c		\
	buffer.c		\
	tmcd_lowlevel.c		\
	helper.c		\
	modules/subdir.c	\
	$(iconv_source)		\
	$(mount_source)

libtmfs_la_LDFLAGS = -pthread @libtmfs_libs@ -version-number 2:9:4 \
	-Wl,--version-script,$(srcdir)/tmfs_versionscript

if NETBSD
libtmfs_la_LIBADD = -lpertmfs -lpuffs
endif

libulockmgr_la_SOURCES = ulockmgr.c
libulockmgr_la_LDFLAGS = -pthread -version-number 1:0:1

EXTRA_DIST = tmfs_versionscript
