/*
    This file defines the kernel interface of TMFS
    Copyright (C) 2001-2008  Miklos Szeredi <miklos@szeredi.hu>

    This program can be distributed under the terms of the GNU GPL.
    See the file COPYING.

    This -- and only this -- header file may also be distributed under
    the terms of the BSD Licence as follows:

    Copyright (C) 2001-2007 Miklos Szeredi. All rights reserved.

    Redistribution and use in source and binary forms, with or without
    modification, are permitted provided that the following conditions
    are met:
    1. Redistributions of source code must retain the above copyright
       notice, this list of conditions and the following disclaimer.
    2. Redistributions in binary form must reproduce the above copyright
       notice, this list of conditions and the following disclaimer in the
       documentation and/or other materials provided with the distribution.

    THIS SOFTWARE IS PROVIDED BY AUTHOR AND CONTRIBUTORS ``AS IS'' AND
    ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
    IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
    ARE DISCLAIMED.  IN NO EVENT SHALL AUTHOR OR CONTRIBUTORS BE LIABLE
    FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
    DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
    OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
    HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
    LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
    OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
    SUCH DAMAGE.
*/

/*
 * This file defines the kernel interface of TMFS
 *
 * Protocol changelog:
 *
 * 7.9:
 *  - new tmfs_getattr_in input argument of GETATTR
 *  - add lk_flags in tmfs_lk_in
 *  - add lock_owner field to tmfs_setattr_in, tmfs_read_in and tmfs_write_in
 *  - add blksize field to tmfs_attr
 *  - add file flags field to tmfs_read_in and tmfs_write_in
 *
 * 7.10
 *  - add nonseekable open flag
 *
 * 7.11
 *  - add IOCTL message
 *  - add unsolicited notification support
 *  - add POLL message and NOTIFY_POLL notification
 *
 * 7.12
 *  - add umask flag to input argument of open, mknod and mkdir
 *  - add notification messages for invalidation of inodes and
 *    directory entries
 *
 * 7.13
 *  - make max number of background requests and congestion threshold
 *    tunables
 *
 * 7.14
 *  - add splice support to tmfs device
 *
 * 7.15
 *  - add store notify
 *  - add retrieve notify
 *
 * 7.16
 *  - add BATCH_FORGET request
 *  - TMFS_IOCTL_UNRESTRICTED shall now return with array of 'struct
 *    tmfs_ioctl_iovec' instead of ambiguous 'struct iovec'
 *  - add TMFS_IOCTL_32BIT flag
 *
 * 7.17
 *  - add TMFS_FLOCK_LOCKS and TMFS_RELEASE_FLOCK_UNLOCK
 *
 * 7.18
 *  - add TMFS_IOCTL_DIR flag
 *  - add TMFS_NOTIFY_DELETE
 *
 * 7.19
 *  - add TMFS_FALLOCATE
 */

#ifndef _LINUX_TMFS_H
#define _LINUX_TMFS_H

#include <sys/types.h>
#define __u64 uint64_t
#define __s64 int64_t
#define __u32 uint32_t
#define __s32 int32_t
#define __u16 uint16_t

/*
 * Version negotiation:
 *
 * Both the kernel and userspace send the version they support in the
 * INIT request and reply respectively.
 *
 * If the major versions match then both shall use the smallest
 * of the two minor versions for communication.
 *
 * If the kernel supports a larger major version, then userspace shall
 * reply with the major version it supports, ignore the rest of the
 * INIT message and expect a new INIT message from the kernel with a
 * matching major version.
 *
 * If the library supports a larger major version, then it shall fall
 * back to the major protocol version sent by the kernel for
 * communication and reply with that major version (and an arbitrary
 * supported minor version).
 */

/** Version number of this interface */
#define TMFS_KERNEL_VERSION 7

/** Minor version number of this interface */
#define TMFS_KERNEL_MINOR_VERSION 19

/** The node ID of the root inode */
#define TMFS_ROOT_ID 1

/* Make sure all structures are padded to 64bit boundary, so 32bit
   userspace works under 64bit kernels */

struct tmfs_attr {
	__u64	ino;
	__u64	size;
	__u64	blocks;
	__u64	atime;
	__u64	mtime;
	__u64	ctime;
	__u32	atimensec;
	__u32	mtimensec;
	__u32	ctimensec;
	__u32	mode;
	__u32	nlink;
	__u32	uid;
	__u32	gid;
	__u32	rdev;
	__u32	blksize;
	__u32	padding;
};

struct tmfs_kstatfs {
	__u64	blocks;
	__u64	bfree;
	__u64	bavail;
	__u64	files;
	__u64	ffree;
	__u32	bsize;
	__u32	namelen;
	__u32	frsize;
	__u32	padding;
	__u32	spare[6];
};

struct tmfs_file_lock {
	__u64	start;
	__u64	end;
	__u32	type;
	__u32	pid; /* tgid */
};

/**
 * Bitmasks for tmfs_setattr_in.valid
 */
#define FATTR_MODE	(1 << 0)
#define FATTR_UID	(1 << 1)
#define FATTR_GID	(1 << 2)
#define FATTR_SIZE	(1 << 3)
#define FATTR_ATIME	(1 << 4)
#define FATTR_MTIME	(1 << 5)
#define FATTR_FH	(1 << 6)
#define FATTR_ATIME_NOW	(1 << 7)
#define FATTR_MTIME_NOW	(1 << 8)
#define FATTR_LOCKOWNER	(1 << 9)

/**
 * Flags returned by the OPEN request
 *
 * FOPEN_DIRECT_IO: bypass page cache for this open file
 * FOPEN_KEEP_CACHE: don't invalidate the data cache on open
 * FOPEN_NONSEEKABLE: the file is not seekable
 */
#define FOPEN_DIRECT_IO		(1 << 0)
#define FOPEN_KEEP_CACHE	(1 << 1)
#define FOPEN_NONSEEKABLE	(1 << 2)

/**
 * INIT request/reply flags
 *
 * TMFS_POSIX_LOCKS: remote locking for POSIX file locks
 * TMFS_EXPORT_SUPPORT: filesystem handles lookups of "." and ".."
 * TMFS_DONT_MASK: don't apply umask to file mode on create operations
 * TMFS_FLOCK_LOCKS: remote locking for BSD style file locks
 */
#define TMFS_ASYNC_READ		(1 << 0)
#define TMFS_POSIX_LOCKS	(1 << 1)
#define TMFS_FILE_OPS		(1 << 2)
#define TMFS_ATOMIC_O_TRUNC	(1 << 3)
#define TMFS_EXPORT_SUPPORT	(1 << 4)
#define TMFS_BIG_WRITES		(1 << 5)
#define TMFS_DONT_MASK		(1 << 6)
#define TMFS_FLOCK_LOCKS	(1 << 10)

/**
 * TMCD INIT request/reply flags
 *
 * TMCD_UNRESTRICTED_IOCTL:  use unrestricted ioctl
 */
#define TMCD_UNRESTRICTED_IOCTL	(1 << 0)

/**
 * Release flags
 */
#define TMFS_RELEASE_FLUSH	(1 << 0)
#define TMFS_RELEASE_FLOCK_UNLOCK	(1 << 1)

/**
 * Getattr flags
 */
#define TMFS_GETATTR_FH		(1 << 0)

/**
 * Lock flags
 */
#define TMFS_LK_FLOCK		(1 << 0)

/**
 * WRITE flags
 *
 * TMFS_WRITE_CACHE: delayed write from page cache, file handle is guessed
 * TMFS_WRITE_LOCKOWNER: lock_owner field is valid
 */
#define TMFS_WRITE_CACHE	(1 << 0)
#define TMFS_WRITE_LOCKOWNER	(1 << 1)

/**
 * Read flags
 */
#define TMFS_READ_LOCKOWNER	(1 << 1)

/**
 * Ioctl flags
 *
 * TMFS_IOCTL_COMPAT: 32bit compat ioctl on 64bit machine
 * TMFS_IOCTL_UNRESTRICTED: not restricted to well-formed ioctls, retry allowed
 * TMFS_IOCTL_RETRY: retry with new iovecs
 * TMFS_IOCTL_32BIT: 32bit ioctl
 * TMFS_IOCTL_DIR: is a directory
 *
 * TMFS_IOCTL_MAX_IOV: maximum of in_iovecs + out_iovecs
 */
#define TMFS_IOCTL_COMPAT	(1 << 0)
#define TMFS_IOCTL_UNRESTRICTED	(1 << 1)
#define TMFS_IOCTL_RETRY	(1 << 2)
#define TMFS_IOCTL_32BIT	(1 << 3)
#define TMFS_IOCTL_DIR		(1 << 4)

#define TMFS_IOCTL_MAX_IOV	256

/**
 * Poll flags
 *
 * TMFS_POLL_SCHEDULE_NOTIFY: request poll notify
 */
#define TMFS_POLL_SCHEDULE_NOTIFY (1 << 0)

enum tmfs_opcode {
	TMFS_LOOKUP	   = 1,
	TMFS_FORGET	   = 2,  /* no reply */
	TMFS_GETATTR	   = 3,
	TMFS_SETATTR	   = 4,
	TMFS_READLINK	   = 5,
	TMFS_SYMLINK	   = 6,
	TMFS_MKNOD	   = 8,
	TMFS_MKDIR	   = 9,
	TMFS_UNLINK	   = 10,
	TMFS_RMDIR	   = 11,
	TMFS_RENAME	   = 12,
	TMFS_LINK	   = 13,
	TMFS_OPEN	   = 14,
	TMFS_READ	   = 15,
	TMFS_WRITE	   = 16,
	TMFS_STATFS	   = 17,
	TMFS_RELEASE       = 18,
	TMFS_FSYNC         = 20,
	TMFS_SETXATTR      = 21,
	TMFS_GETXATTR      = 22,
	TMFS_LISTXATTR     = 23,
	TMFS_REMOVEXATTR   = 24,
	TMFS_FLUSH         = 25,
	TMFS_INIT          = 26,
	TMFS_OPENDIR       = 27,
	TMFS_READDIR       = 28,
	TMFS_RELEASEDIR    = 29,
	TMFS_FSYNCDIR      = 30,
	TMFS_GETLK         = 31,
	TMFS_SETLK         = 32,
	TMFS_SETLKW        = 33,
	TMFS_ACCESS        = 34,
	TMFS_CREATE        = 35,
	TMFS_INTERRUPT     = 36,
	TMFS_BMAP          = 37,
	TMFS_DESTROY       = 38,
	TMFS_IOCTL         = 39,
	TMFS_POLL          = 40,
	TMFS_NOTIFY_REPLY  = 41,
	TMFS_BATCH_FORGET  = 42,
	TMFS_FALLOCATE     = 43,

	/* TMCD specific operations */
	TMCD_INIT          = 4096,
};

enum tmfs_notify_code {
	TMFS_NOTIFY_POLL   = 1,
	TMFS_NOTIFY_INVAL_INODE = 2,
	TMFS_NOTIFY_INVAL_ENTRY = 3,
	TMFS_NOTIFY_STORE = 4,
	TMFS_NOTIFY_RETRIEVE = 5,
	TMFS_NOTIFY_DELETE = 6,
	TMFS_NOTIFY_CODE_MAX,
};

/* The read buffer is required to be at least 8k, but may be much larger */
#define TMFS_MIN_READ_BUFFER 8192

#define TMFS_COMPAT_ENTRY_OUT_SIZE 120

struct tmfs_entry_out {
	__u64	nodeid;		/* Inode ID */
	__u64	generation;	/* Inode generation: nodeid:gen must
				   be unique for the fs's lifetime */
	__u64	entry_valid;	/* Cache timeout for the name */
	__u64	attr_valid;	/* Cache timeout for the attributes */
	__u32	entry_valid_nsec;
	__u32	attr_valid_nsec;
	struct tmfs_attr attr;
};

struct tmfs_forget_in {
	__u64	nlookup;
};

struct tmfs_forget_one {
	__u64	nodeid;
	__u64	nlookup;
};

struct tmfs_batch_forget_in {
	__u32	count;
	__u32	dummy;
};

struct tmfs_getattr_in {
	__u32	getattr_flags;
	__u32	dummy;
	__u64	fh;
};

#define TMFS_COMPAT_ATTR_OUT_SIZE 96

struct tmfs_attr_out {
	__u64	attr_valid;	/* Cache timeout for the attributes */
	__u32	attr_valid_nsec;
	__u32	dummy;
	struct tmfs_attr attr;
};

#define TMFS_COMPAT_MKNOD_IN_SIZE 8

struct tmfs_mknod_in {
	__u32	mode;
	__u32	rdev;
	__u32	umask;
	__u32	padding;
};

struct tmfs_mkdir_in {
	__u32	mode;
	__u32	umask;
};

struct tmfs_rename_in {
	__u64	newdir;
};

struct tmfs_link_in {
	__u64	oldnodeid;
};

struct tmfs_setattr_in {
	__u32	valid;
	__u32	padding;
	__u64	fh;
	__u64	size;
	__u64	lock_owner;
	__u64	atime;
	__u64	mtime;
	__u64	unused2;
	__u32	atimensec;
	__u32	mtimensec;
	__u32	unused3;
	__u32	mode;
	__u32	unused4;
	__u32	uid;
	__u32	gid;
	__u32	unused5;
};

struct tmfs_open_in {
	__u32	flags;
	__u32	unused;
};

struct tmfs_create_in {
	__u32	flags;
	__u32	mode;
	__u32	umask;
	__u32	padding;
};

struct tmfs_open_out {
	__u64	fh;
	__u32	open_flags;
	__u32	padding;
};

struct tmfs_release_in {
	__u64	fh;
	__u32	flags;
	__u32	release_flags;
	__u64	lock_owner;
};

struct tmfs_flush_in {
	__u64	fh;
	__u32	unused;
	__u32	padding;
	__u64	lock_owner;
};

struct tmfs_read_in {
	__u64	fh;
	__u64	offset;
	__u32	size;
	__u32	read_flags;
	__u64	lock_owner;
	__u32	flags;
	__u32	padding;
};

#define TMFS_COMPAT_WRITE_IN_SIZE 24

struct tmfs_write_in {
	__u64	fh;
	__u64	offset;
	__u32	size;
	__u32	write_flags;
	__u64	lock_owner;
	__u32	flags;
	__u32	padding;
};

struct tmfs_write_out {
	__u32	size;
	__u32	padding;
};

#define TMFS_COMPAT_STATFS_SIZE 48

struct tmfs_statfs_out {
	struct tmfs_kstatfs st;
};

struct tmfs_fsync_in {
	__u64	fh;
	__u32	fsync_flags;
	__u32	padding;
};

struct tmfs_setxattr_in {
	__u32	size;
	__u32	flags;
};

struct tmfs_getxattr_in {
	__u32	size;
	__u32	padding;
};

struct tmfs_getxattr_out {
	__u32	size;
	__u32	padding;
};

struct tmfs_lk_in {
	__u64	fh;
	__u64	owner;
	struct tmfs_file_lock lk;
	__u32	lk_flags;
	__u32	padding;
};

struct tmfs_lk_out {
	struct tmfs_file_lock lk;
};

struct tmfs_access_in {
	__u32	mask;
	__u32	padding;
};

struct tmfs_init_in {
	__u32	major;
	__u32	minor;
	__u32	max_readahead;
	__u32	flags;
};

struct tmfs_init_out {
	__u32	major;
	__u32	minor;
	__u32	max_readahead;
	__u32	flags;
	__u16   max_background;
	__u16   congestion_threshold;
	__u32	max_write;
};

#define TMCD_INIT_INFO_MAX 4096

struct tmcd_init_in {
	__u32	major;
	__u32	minor;
	__u32	unused;
	__u32	flags;
};

struct tmcd_init_out {
	__u32	major;
	__u32	minor;
	__u32	unused;
	__u32	flags;
	__u32	max_read;
	__u32	max_write;
	__u32	dev_major;		/* chardev major */
	__u32	dev_minor;		/* chardev minor */
	__u32	spare[10];
};

struct tmfs_interrupt_in {
	__u64	unique;
};

struct tmfs_bmap_in {
	__u64	block;
	__u32	blocksize;
	__u32	padding;
};

struct tmfs_bmap_out {
	__u64	block;
};

struct tmfs_ioctl_in {
	__u64	fh;
	__u32	flags;
	__u32	cmd;
	__u64	arg;
	__u32	in_size;
	__u32	out_size;
};

struct tmfs_ioctl_iovec {
	__u64	base;
	__u64	len;
};

struct tmfs_ioctl_out {
	__s32	result;
	__u32	flags;
	__u32	in_iovs;
	__u32	out_iovs;
};

struct tmfs_poll_in {
	__u64	fh;
	__u64	kh;
	__u32	flags;
	__u32   padding;
};

struct tmfs_poll_out {
	__u32	revents;
	__u32	padding;
};

struct tmfs_notify_poll_wakeup_out {
	__u64	kh;
};

struct tmfs_fallocate_in {
	__u64	fh;
	__u64	offset;
	__u64	length;
	__u32	mode;
	__u32	padding;
};

struct tmfs_in_header {
	__u32	len;
	__u32	opcode;
	__u64	unique;
	__u64	nodeid;
	__u32	uid;
	__u32	gid;
	__u32	pid;
	__u32	padding;
};

struct tmfs_out_header {
	__u32	len;
	__s32	error;
	__u64	unique;
};

struct tmfs_dirent {
	__u64	ino;
	__u64	off;
	__u32	namelen;
	__u32	type;
	char name[];
};

#define TMFS_NAME_OFFSET offsetof(struct tmfs_dirent, name)
#define TMFS_DIRENT_ALIGN(x) (((x) + sizeof(__u64) - 1) & ~(sizeof(__u64) - 1))
#define TMFS_DIRENT_SIZE(d) \
	TMFS_DIRENT_ALIGN(TMFS_NAME_OFFSET + (d)->namelen)

struct tmfs_notify_inval_inode_out {
	__u64	ino;
	__s64	off;
	__s64	len;
};

struct tmfs_notify_inval_entry_out {
	__u64	parent;
	__u32	namelen;
	__u32	padding;
};

struct tmfs_notify_delete_out {
	__u64	parent;
	__u64	child;
	__u32	namelen;
	__u32	padding;
};

struct tmfs_notify_store_out {
	__u64	nodeid;
	__u64	offset;
	__u32	size;
	__u32	padding;
};

struct tmfs_notify_retrieve_out {
	__u64	notify_unique;
	__u64	nodeid;
	__u64	offset;
	__u32	size;
	__u32	padding;
};

/* Matches the size of tmfs_write_in */
struct tmfs_notify_retrieve_in {
	__u64	dummy1;
	__u64	offset;
	__u32	size;
	__u32	dummy2;
	__u64	dummy3;
	__u64	dummy4;
};

#endif /* _LINUX_TMFS_H */
