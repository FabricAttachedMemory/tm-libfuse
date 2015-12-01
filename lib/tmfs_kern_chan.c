/*
  TMFS: Filesystem in Userspace
  Copyright (C) 2001-2007  Miklos Szeredi <miklos@szeredi.hu>

  This program can be distributed under the terms of the GNU LGPLv2.
  See the file COPYING.LIB
*/

#include "tmfs_lowlevel.h"
#include "tmfs_kernel.h"
#include "tmfs_i.h"

#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <assert.h>

static int tmfs_kern_chan_receive(struct tmfs_chan **chp, char *buf,
				  size_t size)
{
	struct tmfs_chan *ch = *chp;
	int err;
	ssize_t res;
	struct tmfs_session *se = tmfs_chan_session(ch);
	assert(se != NULL);

restart:
	res = read(tmfs_chan_fd(ch), buf, size);
	err = errno;

	if (tmfs_session_exited(se))
		return 0;
	if (res == -1) {
		/* ENOENT means the operation was interrupted, it's safe
		   to restart */
		if (err == ENOENT)
			goto restart;

		if (err == ENODEV) {
			tmfs_session_exit(se);
			return 0;
		}
		/* Errors occurring during normal operation: EINTR (read
		   interrupted), EAGAIN (nonblocking I/O), ENODEV (filesystem
		   umounted) */
		if (err != EINTR && err != EAGAIN)
			perror("tmfs: reading device");
		return -err;
	}
	if ((size_t) res < sizeof(struct tmfs_in_header)) {
		fprintf(stderr, "short read on tmfs device\n");
		return -EIO;
	}
	return res;
}

static int tmfs_kern_chan_send(struct tmfs_chan *ch, const struct iovec iov[],
			       size_t count)
{
	if (iov) {
		ssize_t res = writev(tmfs_chan_fd(ch), iov, count);
		int err = errno;

		if (res == -1) {
			struct tmfs_session *se = tmfs_chan_session(ch);

			assert(se != NULL);

			/* ENOENT means the operation was interrupted */
			if (!tmfs_session_exited(se) && err != ENOENT)
				perror("tmfs: writing device");
			return -err;
		}
	}
	return 0;
}

static void tmfs_kern_chan_destroy(struct tmfs_chan *ch)
{
	int fd = tmfs_chan_fd(ch);

	if (fd != -1)
		close(fd);
}

#define MIN_BUFSIZE 0x21000

struct tmfs_chan *tmfs_kern_chan_new(int fd)
{
	struct tmfs_chan_ops op = {
		.receive = tmfs_kern_chan_receive,
		.send = tmfs_kern_chan_send,
		.destroy = tmfs_kern_chan_destroy,
	};
	size_t bufsize = getpagesize() + 0x1000;
	bufsize = bufsize < MIN_BUFSIZE ? MIN_BUFSIZE : bufsize;
	return tmfs_chan_new(&op, fd, bufsize, NULL);
}
