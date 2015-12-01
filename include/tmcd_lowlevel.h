/*
  TMCD: Character device in Userspace
  Copyright (C) 2008-2009  SUSE Linux Products GmbH
  Copyright (C) 2008-2009  Tejun Heo <tj@kernel.org>

  This program can be distributed under the terms of the GNU LGPLv2.
  See the file COPYING.LIB.

  Read example/tmcdxmp.c for usages.
*/

#ifndef _TMCD_LOWLEVEL_H_
#define _TMCD_LOWLEVEL_H_

#ifndef TMFS_USE_VERSION
#define TMFS_USE_VERSION 29
#endif

#include "tmfs_lowlevel.h"

#include <fcntl.h>
#include <sys/types.h>
#include <sys/uio.h>

#ifdef __cplusplus
extern "C" {
#endif

#define TMCD_UNRESTRICTED_IOCTL		(1 << 0) /* use unrestricted ioctl */

struct tmfs_session;

struct tmcd_info {
	unsigned	dev_major;
	unsigned	dev_minor;
	unsigned	dev_info_argc;
	const char	**dev_info_argv;
	unsigned	flags;
};

/*
 * Most ops behave almost identically to the matching tmfs_lowlevel
 * ops except that they don't take @ino.
 *
 * init_done	: called after initialization is complete
 * read/write	: always direct IO, simultaneous operations allowed
 * ioctl	: might be in unrestricted mode depending on ci->flags
 */
struct tmcd_lowlevel_ops {
	void (*init) (void *userdata, struct tmfs_conn_info *conn);
	void (*init_done) (void *userdata);
	void (*destroy) (void *userdata);
	void (*open) (tmfs_req_t req, struct tmfs_file_info *fi);
	void (*read) (tmfs_req_t req, size_t size, off_t off,
		      struct tmfs_file_info *fi);
	void (*write) (tmfs_req_t req, const char *buf, size_t size, off_t off,
		       struct tmfs_file_info *fi);
	void (*flush) (tmfs_req_t req, struct tmfs_file_info *fi);
	void (*release) (tmfs_req_t req, struct tmfs_file_info *fi);
	void (*fsync) (tmfs_req_t req, int datasync, struct tmfs_file_info *fi);
	void (*ioctl) (tmfs_req_t req, int cmd, void *arg,
		       struct tmfs_file_info *fi, unsigned int flags,
		       const void *in_buf, size_t in_bufsz, size_t out_bufsz);
	void (*poll) (tmfs_req_t req, struct tmfs_file_info *fi,
		      struct tmfs_pollhandle *ph);
};

struct tmfs_session *tmcd_lowlevel_new(struct tmfs_args *args,
				       const struct tmcd_info *ci,
				       const struct tmcd_lowlevel_ops *clop,
				       void *userdata);

struct tmfs_session *tmcd_lowlevel_setup(int argc, char *argv[],
					 const struct tmcd_info *ci,
					 const struct tmcd_lowlevel_ops *clop,
					 int *multithreaded, void *userdata);

void tmcd_lowlevel_teardown(struct tmfs_session *se);

int tmcd_lowlevel_main(int argc, char *argv[], const struct tmcd_info *ci,
		       const struct tmcd_lowlevel_ops *clop, void *userdata);

#ifdef __cplusplus
}
#endif

#endif /* _TMCD_LOWLEVEL_H_ */
