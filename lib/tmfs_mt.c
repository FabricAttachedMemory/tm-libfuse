/*
  TMFS: Filesystem in Userspace
  Copyright (C) 2001-2007  Miklos Szeredi <miklos@szeredi.hu>

  This program can be distributed under the terms of the GNU LGPLv2.
  See the file COPYING.LIB.
*/

#include "tmfs_i.h"
#include "tmfs_misc.h"
#include "tmfs_lowlevel.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <assert.h>

struct procdata {
	struct tmfs *f;
	struct tmfs_chan *prevch;
	struct tmfs_session *prevse;
	tmfs_processor_t proc;
	void *data;
};

static void mt_session_proc(void *data, const char *buf, size_t len,
			    struct tmfs_chan *ch)
{
	struct procdata *pd = (struct procdata *) data;
	struct tmfs_cmd *cmd = *(struct tmfs_cmd **) buf;

	(void) len;
	(void) ch;
	pd->proc(pd->f, cmd, pd->data);
}

static void mt_session_exit(void *data, int val)
{
	struct procdata *pd = (struct procdata *) data;
	if (val)
		tmfs_session_exit(pd->prevse);
	else
		tmfs_session_reset(pd->prevse);
}

static int mt_session_exited(void *data)
{
	struct procdata *pd = (struct procdata *) data;
	return tmfs_session_exited(pd->prevse);
}

static int mt_chan_receive(struct tmfs_chan **chp, char *buf, size_t size)
{
	struct tmfs_cmd *cmd;
	struct procdata *pd = (struct procdata *) tmfs_chan_data(*chp);

	assert(size >= sizeof(cmd));

	cmd = tmfs_read_cmd(pd->f);
	if (cmd == NULL)
		return 0;

	*(struct tmfs_cmd **) buf = cmd;

	return sizeof(cmd);
}

int tmfs_loop_mt_proc(struct tmfs *f, tmfs_processor_t proc, void *data)
{
	int res;
	struct procdata pd;
	struct tmfs_session *prevse = tmfs_get_session(f);
	struct tmfs_session *se;
	struct tmfs_chan *prevch = tmfs_session_next_chan(prevse, NULL);
	struct tmfs_chan *ch;
	struct tmfs_session_ops sop = {
		.exit = mt_session_exit,
		.exited = mt_session_exited,
		.process = mt_session_proc,
	};
	struct tmfs_chan_ops cop = {
		.receive = mt_chan_receive,
	};

	pd.f = f;
	pd.prevch = prevch;
	pd.prevse = prevse;
	pd.proc = proc;
	pd.data = data;

	se = tmfs_session_new(&sop, &pd);
	if (se == NULL)
		return -1;

	ch = tmfs_chan_new(&cop, tmfs_chan_fd(prevch),
			   sizeof(struct tmfs_cmd *), &pd);
	if (ch == NULL) {
		tmfs_session_destroy(se);
		return -1;
	}
	tmfs_session_add_chan(se, ch);
	res = tmfs_session_loop_mt(se);
	tmfs_session_destroy(se);
	return res;
}

int tmfs_loop_mt(struct tmfs *f)
{
	if (f == NULL)
		return -1;

	int res = tmfs_start_cleanup_thread(f);
	if (res)
		return -1;

	res = tmfs_session_loop_mt(tmfs_get_session(f));
	tmfs_stop_cleanup_thread(f);
	return res;
}

TMFS_SYMVER(".symver tmfs_loop_mt_proc,__tmfs_loop_mt@");
