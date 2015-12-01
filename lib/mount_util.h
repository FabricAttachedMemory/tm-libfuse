/*
  TMFS: Filesystem in Userspace
  Copyright (C) 2001-2007  Miklos Szeredi <miklos@szeredi.hu>

  This program can be distributed under the terms of the GNU LGPLv2.
  See the file COPYING.LIB.
*/

#include <sys/types.h>

int tmfs_mnt_add_mount(const char *progname, const char *fsname,
		       const char *mnt, const char *type, const char *opts);
int tmfs_mnt_remove_mount(const char *progname, const char *mnt);
int tmfs_mnt_umount(const char *progname, const char *abs_mnt,
		    const char *rel_mnt, int lazy);
char *tmfs_mnt_resolve_path(const char *progname, const char *orig);
int tmfs_mnt_check_empty(const char *progname, const char *mnt,
			 mode_t rootmode, off_t rootsize);
int tmfs_mnt_check_tmfsblk(void);
