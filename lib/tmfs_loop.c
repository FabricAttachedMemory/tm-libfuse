/*
  TMFS: Filesystem in Userspace
  Copyright (C) 2001-2007  Miklos Szeredi <miklos@szeredi.hu>

  This program can be distributed under the terms of the GNU LGPLv2.
  See the file COPYING.LIB
*/

#include "tmfs_lowlevel.h"

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

int tmfs_session_loop(struct tmfs_session *se)
{
	int res = 0;
	struct tmfs_chan *ch = tmfs_session_next_chan(se, NULL);
	size_t bufsize = tmfs_chan_bufsize(ch);
	char *buf = (char *) malloc(bufsize);
	if (!buf) {
		fprintf(stderr, "tmfs: failed to allocate read buffer\n");
		return -1;
	}

	while (!tmfs_session_exited(se)) {
		struct tmfs_chan *tmpch = ch;
		struct tmfs_buf fbuf = {
			.mem = buf,
			.size = bufsize,
		};

		res = tmfs_session_receive_buf(se, &fbuf, &tmpch);

		if (res == -EINTR)
			continue;
		if (res <= 0)
			break;

		tmfs_session_process_buf(se, &fbuf, tmpch);
	}

	free(buf);
	tmfs_session_reset(se);
	return res < 0 ? -1 : 0;
}
