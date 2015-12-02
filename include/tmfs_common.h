/*
  TMFS: Filesystem in Userspace
  Copyright (C) 2001-2007  Miklos Szeredi <miklos@szeredi.hu>

  This program can be distributed under the terms of the GNU LGPLv2.
  See the file COPYING.LIB.
*/

/** @file */

#if !defined(_TMFS_H_) && !defined(_TMFS_LOWLEVEL_H_)
#error "Never include <tmfs_common.h> directly; use <tmfs.h> or <tmfs_lowlevel.h> instead."
#endif

#ifndef _TMFS_COMMON_H_
#define _TMFS_COMMON_H_

#include "tmfs_opt.h"
#include <stdint.h>
#include <sys/types.h>

/** Major version of TMFS library interface */
#define TMFS_MAJOR_VERSION 2

/** Minor version of TMFS library interface */
#define TMFS_MINOR_VERSION 9

#define TMFS_MAKE_VERSION(maj, min)  ((maj) * 10 + (min))
#define TMFS_VERSION TMFS_MAKE_VERSION(TMFS_MAJOR_VERSION, TMFS_MINOR_VERSION)

/* This interface uses 64 bit off_t */
#if _FILE_OFFSET_BITS != 64
#error Please add -D_FILE_OFFSET_BITS=64 to your compile flags!
#endif

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Information about open files
 *
 * Changed in version 2.5
 */
struct tmfs_file_info {
	/** Open flags.	 Available in open() and release() */
	int flags;

	/** Old file handle, don't use */
	unsigned long fh_old;

	/** In case of a write operation indicates if this was caused by a
	    writepage */
	int writepage;

	/** Can be filled in by open, to use direct I/O on this file.
	    Introduced in version 2.4 */
	unsigned int direct_io : 1;

	/** Can be filled in by open, to indicate, that cached file data
	    need not be invalidated.  Introduced in version 2.4 */
	unsigned int keep_cache : 1;

	/** Indicates a flush operation.  Set in flush operation, also
	    maybe set in highlevel lock operation and lowlevel release
	    operation.	Introduced in version 2.6 */
	unsigned int flush : 1;

	/** Can be filled in by open, to indicate that the file is not
	    seekable.  Introduced in version 2.8 */
	unsigned int nonseekable : 1;

	/* Indicates that flock locks for this file should be
	   released.  If set, lock_owner shall contain a valid value.
	   May only be set in ->release().  Introduced in version
	   2.9 */
	unsigned int flock_release : 1;

	/** Padding.  Do not use*/
	unsigned int padding : 27;

	/** File handle.  May be filled in by filesystem in open().
	    Available in all other file operations */
	uint64_t fh;

	/** Lock owner id.  Available in locking operations and flush */
	uint64_t lock_owner;
};

/**
 * Capability bits for 'tmfs_conn_info.capable' and 'tmfs_conn_info.want'
 *
 * TMFS_CAP_ASYNC_READ: filesystem supports asynchronous read requests
 * TMFS_CAP_POSIX_LOCKS: filesystem supports "remote" locking
 * TMFS_CAP_ATOMIC_O_TRUNC: filesystem handles the O_TRUNC open flag
 * TMFS_CAP_EXPORT_SUPPORT: filesystem handles lookups of "." and ".."
 * TMFS_CAP_BIG_WRITES: filesystem can handle write size larger than 4kB
 * TMFS_CAP_DONT_MASK: don't apply umask to file mode on create operations
 * TMFS_CAP_SPLICE_WRITE: ability to use splice() to write to the tmfs device
 * TMFS_CAP_SPLICE_MOVE: ability to move data to the tmfs device with splice()
 * TMFS_CAP_SPLICE_READ: ability to use splice() to read from the tmfs device
 * TMFS_CAP_IOCTL_DIR: ioctl support on directories
 */
#define TMFS_CAP_ASYNC_READ	(1 << 0)
#define TMFS_CAP_POSIX_LOCKS	(1 << 1)
#define TMFS_CAP_ATOMIC_O_TRUNC	(1 << 3)
#define TMFS_CAP_EXPORT_SUPPORT	(1 << 4)
#define TMFS_CAP_BIG_WRITES	(1 << 5)
#define TMFS_CAP_DONT_MASK	(1 << 6)
#define TMFS_CAP_SPLICE_WRITE	(1 << 7)
#define TMFS_CAP_SPLICE_MOVE	(1 << 8)
#define TMFS_CAP_SPLICE_READ	(1 << 9)
#define TMFS_CAP_FLOCK_LOCKS	(1 << 10)
#define TMFS_CAP_IOCTL_DIR	(1 << 11)

/**
 * Ioctl flags
 *
 * TMFS_IOCTL_COMPAT: 32bit compat ioctl on 64bit machine
 * TMFS_IOCTL_UNRESTRICTED: not restricted to well-formed ioctls, retry allowed
 * TMFS_IOCTL_RETRY: retry with new iovecs
 * TMFS_IOCTL_DIR: is a directory
 *
 * TMFS_IOCTL_MAX_IOV: maximum of in_iovecs + out_iovecs
 */
#define TMFS_IOCTL_COMPAT	(1 << 0)
#define TMFS_IOCTL_UNRESTRICTED	(1 << 1)
#define TMFS_IOCTL_RETRY	(1 << 2)
#define TMFS_IOCTL_DIR		(1 << 4)

#define TMFS_IOCTL_MAX_IOV	256

/**
 * Connection information, passed to the ->init() method
 *
 * Some of the elements are read-write, these can be changed to
 * indicate the value requested by the filesystem.  The requested
 * value must usually be smaller than the indicated value.
 */
struct tmfs_conn_info {
	/**
	 * Major version of the protocol (read-only)
	 */
	unsigned proto_major;

	/**
	 * Minor version of the protocol (read-only)
	 */
	unsigned proto_minor;

	/**
	 * Is asynchronous read supported (read-write)
	 */
	unsigned async_read;

	/**
	 * Maximum size of the write buffer
	 */
	unsigned max_write;

	/**
	 * Maximum readahead
	 */
	unsigned max_readahead;

	/**
	 * Capability flags, that the kernel supports
	 */
	unsigned capable;

	/**
	 * Capability flags, that the filesystem wants to enable
	 */
	unsigned want;

	/**
	 * Maximum number of backgrounded requests
	 */
	unsigned max_background;

	/**
	 * Kernel congestion threshold parameter
	 */
	unsigned congestion_threshold;

	/**
	 * For future use.
	 */
	unsigned reserved[23];
};

struct tmfs_session;
struct tmfs_chan;
struct tmfs_pollhandle;

/**
 * Create a TMFS mountpoint
 *
 * Returns a control file descriptor suitable for passing to
 * tmfs_new()
 *
 * @param mountpoint the mount point path
 * @param args argument vector
 * @return the communication channel on success, NULL on failure
 */
struct tmfs_chan *tmfs_mount(const char *mountpoint, struct tmfs_args *args);

/**
 * Umount a TMFS mountpoint
 *
 * @param mountpoint the mount point path
 * @param ch the communication channel
 */
void tmfs_unmount(const char *mountpoint, struct tmfs_chan *ch);

/**
 * Parse common options
 *
 * The following options are parsed:
 *
 *   '-f'	     foreground
 *   '-d' '-odebug'  foreground, but keep the debug option
 *   '-s'	     single threaded
 *   '-h' '--help'   help
 *   '-ho'	     help without header
 *   '-ofsname=..'   file system name, if not present, then set to the program
 *		     name
 *
 * All parameters may be NULL
 *
 * @param args argument vector
 * @param mountpoint the returned mountpoint, should be freed after use
 * @param multithreaded set to 1 unless the '-s' option is present
 * @param foreground set to 1 if one of the relevant options is present
 * @return 0 on success, -1 on failure
 */
int tmfs_parse_cmdline(struct tmfs_args *args, char **mountpoint,
		       int *multithreaded, int *foreground);

/**
 * Go into the background
 *
 * @param foreground if true, stay in the foreground
 * @return 0 on success, -1 on failure
 */
int tmfs_daemonize(int foreground);

/**
 * Get the version of the library
 *
 * @return the version
 */
int tmfs_version(void);

/**
 * Destroy poll handle
 *
 * @param ph the poll handle
 */
void tmfs_pollhandle_destroy(struct tmfs_pollhandle *ph);

/* ----------------------------------------------------------- *
 * Data buffer						       *
 * ----------------------------------------------------------- */

/**
 * Buffer flags
 */
enum tmfs_buf_flags {
	/**
	 * Buffer contains a file descriptor
	 *
	 * If this flag is set, the .fd field is valid, otherwise the
	 * .mem fields is valid.
	 */
	TMFS_BUF_IS_FD		= (1 << 1),

	/**
	 * Seek on the file descriptor
	 *
	 * If this flag is set then the .pos field is valid and is
	 * used to seek to the given offset before performing
	 * operation on file descriptor.
	 */
	TMFS_BUF_FD_SEEK	= (1 << 2),

	/**
	 * Retry operation on file descriptor
	 *
	 * If this flag is set then retry operation on file descriptor
	 * until .size bytes have been copied or an error or EOF is
	 * detected.
	 */
	TMFS_BUF_FD_RETRY	= (1 << 3),
};

/**
 * Buffer copy flags
 */
enum tmfs_buf_copy_flags {
	/**
	 * Don't use splice(2)
	 *
	 * Always fall back to using read and write instead of
	 * splice(2) to copy data from one file descriptor to another.
	 *
	 * If this flag is not set, then only fall back if splice is
	 * unavailable.
	 */
	TMFS_BUF_NO_SPLICE	= (1 << 1),

	/**
	 * Force splice
	 *
	 * Always use splice(2) to copy data from one file descriptor
	 * to another.  If splice is not available, return -EINVAL.
	 */
	TMFS_BUF_FORCE_SPLICE	= (1 << 2),

	/**
	 * Try to move data with splice.
	 *
	 * If splice is used, try to move pages from the source to the
	 * destination instead of copying.  See documentation of
	 * SPLICE_F_MOVE in splice(2) man page.
	 */
	TMFS_BUF_SPLICE_MOVE	= (1 << 3),

	/**
	 * Don't block on the pipe when copying data with splice
	 *
	 * Makes the operations on the pipe non-blocking (if the pipe
	 * is full or empty).  See SPLICE_F_NONBLOCK in the splice(2)
	 * man page.
	 */
	TMFS_BUF_SPLICE_NONBLOCK= (1 << 4),
};

/**
 * Single data buffer
 *
 * Generic data buffer for I/O, extended attributes, etc...  Data may
 * be supplied as a memory pointer or as a file descriptor
 */
struct tmfs_buf {
	/**
	 * Size of data in bytes
	 */
	size_t size;

	/**
	 * Buffer flags
	 */
	enum tmfs_buf_flags flags;

	/**
	 * Memory pointer
	 *
	 * Used unless TMFS_BUF_IS_FD flag is set.
	 */
	void *mem;

	/**
	 * File descriptor
	 *
	 * Used if TMFS_BUF_IS_FD flag is set.
	 */
	int fd;

	/**
	 * File position
	 *
	 * Used if TMFS_BUF_FD_SEEK flag is set.
	 */
	off_t pos;
};

/**
 * Data buffer vector
 *
 * An array of data buffers, each containing a memory pointer or a
 * file descriptor.
 *
 * Allocate dynamically to add more than one buffer.
 */
struct tmfs_bufvec {
	/**
	 * Number of buffers in the array
	 */
	size_t count;

	/**
	 * Index of current buffer within the array
	 */
	size_t idx;

	/**
	 * Current offset within the current buffer
	 */
	size_t off;

	/**
	 * Array of buffers
	 */
	struct tmfs_buf buf[1];
};

/* Initialize bufvec with a single buffer of given size */
#define TMFS_BUFVEC_INIT(size__) 				\
	((struct tmfs_bufvec) {					\
		/* .count= */ 1,				\
		/* .idx =  */ 0,				\
		/* .off =  */ 0,				\
		/* .buf =  */ { /* [0] = */ {			\
			/* .size =  */ (size__),		\
			/* .flags = */ (enum tmfs_buf_flags) 0,	\
			/* .mem =   */ NULL,			\
			/* .fd =    */ -1,			\
			/* .pos =   */ 0,			\
		} }						\
	} )

/**
 * Get total size of data in a tmfs buffer vector
 *
 * @param bufv buffer vector
 * @return size of data
 */
size_t tmfs_buf_size(const struct tmfs_bufvec *bufv);

/**
 * Copy data from one buffer vector to another
 *
 * @param dst destination buffer vector
 * @param src source buffer vector
 * @param flags flags controlling the copy
 * @return actual number of bytes copied or -errno on error
 */
ssize_t tmfs_buf_copy(struct tmfs_bufvec *dst, struct tmfs_bufvec *src,
		      enum tmfs_buf_copy_flags flags);

/* ----------------------------------------------------------- *
 * Signal handling					       *
 * ----------------------------------------------------------- */

/**
 * Exit session on HUP, TERM and INT signals and ignore PIPE signal
 *
 * Stores session in a global variable.	 May only be called once per
 * process until tmfs_remove_signal_handlers() is called.
 *
 * @param se the session to exit
 * @return 0 on success, -1 on failure
 */
int tmfs_set_signal_handlers(struct tmfs_session *se);

/**
 * Restore default signal handlers
 *
 * Resets global session.  After this tmfs_set_signal_handlers() may
 * be called again.
 *
 * @param se the same session as given in tmfs_set_signal_handlers()
 */
void tmfs_remove_signal_handlers(struct tmfs_session *se);

/* ----------------------------------------------------------- *
 * Compatibility stuff					       *
 * ----------------------------------------------------------- */

#if TMFS_USE_VERSION < 26
#    ifdef __FreeBSD__
#	 if TMFS_USE_VERSION < 25
#	     error On FreeBSD API version 25 or greater must be used
#	 endif
#    endif
#    include "tmfs_common_compat.h"
#    undef TMFS_MINOR_VERSION
#    undef tmfs_main
#    define tmfs_unmount tmfs_unmount_compat22
#    if TMFS_USE_VERSION == 25
#	 define TMFS_MINOR_VERSION 5
#	 define tmfs_mount tmfs_mount_compat25
#    elif TMFS_USE_VERSION == 24 || TMFS_USE_VERSION == 22
#	 define TMFS_MINOR_VERSION 4
#	 define tmfs_mount tmfs_mount_compat22
#    elif TMFS_USE_VERSION == 21
#	 define TMFS_MINOR_VERSION 1
#	 define tmfs_mount tmfs_mount_compat22
#    elif TMFS_USE_VERSION == 11
#	 warning Compatibility with API version 11 is deprecated
#	 undef TMFS_MAJOR_VERSION
#	 define TMFS_MAJOR_VERSION 1
#	 define TMFS_MINOR_VERSION 1
#	 define tmfs_mount tmfs_mount_compat1
#    else
#	 error Compatibility with API version other than 21, 22, 24, 25 and 11 not supported
#    endif
#endif

#ifdef __cplusplus
}
#endif

#endif /* _TMFS_COMMON_H_ */
