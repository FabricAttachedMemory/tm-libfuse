## Process this file with automake to produce Makefile.in

AM_CPPFLAGS = -D_FILE_OFFSET_BITS=64 
bin_PROGRAMS = tmfsrmount ulockmgr_server
noinst_PROGRAMS = mount.tmfs

# we re-use mount_util.c from the library, but do want to keep ourself
# as stand-alone as possible. in order to make an out-of-source build
# possible, we "generate" the file from its original location by
# copying it over.
tmfsrmount_SOURCES = tmfsrmount.c mount_util.c
tmfsrmount_CPPFLAGS = -I$(top_srcdir)/lib
BUILT_SOURCES = mount_util.c
mount_util.c: $(top_srcdir)/lib/mount_util.c
	@cp $(top_srcdir)/lib/mount_util.c .

mount_tmfs_SOURCES = mount.tmfs.c

ulockmgr_server_SOURCES = ulockmgr_server.c
ulockmgr_server_CPPFLAGS = -D_FILE_OFFSET_BITS=64 -D_REENTRANT 
ulockmgr_server_LDFLAGS = -pthread

install-exec-hook:
	-chmod u+s $(DESTDIR)$(bindir)/tmfsrmount
	@if test ! -e $(DESTDIR)/dev/tmfs; then \
		$(MKDIR_P) $(DESTDIR)/dev; \
		echo "mknod $(DESTDIR)/dev/tmfs -m 0666 c 10 240 || true"; \
		mknod $(DESTDIR)/dev/tmfs -m 0666 c 10 240 || true; \
	fi

EXTRA_DIST = udev.rules init_script

MOUNT_TMFS_PATH = @MOUNT_TMFS_PATH@
UDEV_RULES_PATH = @UDEV_RULES_PATH@
INIT_D_PATH = @INIT_D_PATH@

install-exec-local:
	$(MKDIR_P) $(DESTDIR)$(MOUNT_TMFS_PATH)
	$(INSTALL_PROGRAM) $(builddir)/mount.tmfs $(DESTDIR)$(MOUNT_TMFS_PATH)/mount.tmfs
	$(MKDIR_P) $(DESTDIR)$(INIT_D_PATH)
	$(INSTALL_SCRIPT) $(srcdir)/init_script $(DESTDIR)$(INIT_D_PATH)/tmfs
	@if test -x /usr/sbin/update-rc.d; then \
		echo "/usr/sbin/update-rc.d tmfs start 34 S . start 41 0 6 . || true"; \
		/usr/sbin/update-rc.d tmfs start 34 S . start 41 0 6 . || true; \
	fi

install-data-local:
	$(MKDIR_P) $(DESTDIR)$(UDEV_RULES_PATH)
	$(INSTALL_DATA) $(srcdir)/udev.rules $(DESTDIR)$(UDEV_RULES_PATH)/99-tmfs.rules

uninstall-local:
	rm -f $(DESTDIR)$(MOUNT_TMFS_PATH)/mount.tmfs
	rm -f $(DESTDIR)$(UDEV_RULES_PATH)/99-tmfs.rules
	rm -f $(DESTDIR)$(INIT_D_PATH)/tmfs
	@if test -x /usr/sbin/update-rc.d; then \
		echo "/usr/sbin/update-rc.d tmfs remove || true"; \
		/usr/sbin/update-rc.d tmfs remove || true; \
	fi
