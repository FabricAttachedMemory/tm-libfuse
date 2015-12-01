/*
  TMFS: Filesystem in Userspace
  Copyright (C) 2001-2007  Miklos Szeredi <miklos@szeredi.hu>

  This program can be distributed under the terms of the GNU LGPLv2.
  See the file COPYING.LIB
*/

#include "tmfs_i.h"
#include "tmfs_misc.h"
#include "tmfs_common_compat.h"
#include "tmfs_lowlevel_compat.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <errno.h>

struct tmfs_chan {
	struct tmfs_chan_ops op;

	struct tmfs_session *se;

	int fd;

	size_t bufsize;

	void *data;

	int compat;
};

struct tmfs_session *tmfs_session_new(struct tmfs_session_ops *op, void *data)
{
	struct tmfs_session *se = (struct tmfs_session *) malloc(sizeof(*se));
	if (se == NULL) {
		fprintf(stderr, "tmfs: failed to allocate session\n");
		return NULL;
	}

	memset(se, 0, sizeof(*se));
	se->op = *op;
	se->data = data;

	return se;
}

void tmfs_session_add_chan(struct tmfs_session *se, struct tmfs_chan *ch)
{
	assert(se->ch == NULL);
	assert(ch->se == NULL);
	se->ch = ch;
	ch->se = se;
}

void tmfs_session_remove_chan(struct tmfs_chan *ch)
{
	struct tmfs_session *se = ch->se;
	if (se) {
		assert(se->ch == ch);
		se->ch = NULL;
		ch->se = NULL;
	}
}

struct tmfs_chan *tmfs_session_next_chan(struct tmfs_session *se,
					 struct tmfs_chan *ch)
{
	assert(ch == NULL || ch == se->ch);
	if (ch == NULL)
		return se->ch;
	else
		return NULL;
}

void tmfs_session_process(struct tmfs_session *se, const char *buf, size_t len,
			  struct tmfs_chan *ch)
{
	se->op.process(se->data, buf, len, ch);
}

void tmfs_session_process_buf(struct tmfs_session *se,
			      const struct tmfs_buf *buf, struct tmfs_chan *ch)
{
	if (se->process_buf) {
		se->process_buf(se->data, buf, ch);
	} else {
		assert(!(buf->flags & TMFS_BUF_IS_FD));
		tmfs_session_process(se->data, buf->mem, buf->size, ch);
	}
}

int tmfs_session_receive_buf(struct tmfs_session *se, struct tmfs_buf *buf,
			     struct tmfs_chan **chp)
{
	int res;

	if (se->receive_buf) {
		res = se->receive_buf(se, buf, chp);
	} else {
		res = tmfs_chan_recv(chp, buf->mem, buf->size);
		if (res > 0)
			buf->size = res;
	}

	return res;
}


void tmfs_session_destroy(struct tmfs_session *se)
{
	if (se->op.destroy)
		se->op.destroy(se->data);
	if (se->ch != NULL)
		tmfs_chan_destroy(se->ch);
	free(se);
}

void tmfs_session_exit(struct tmfs_session *se)
{
	if (se->op.exit)
		se->op.exit(se->data, 1);
	se->exited = 1;
}

void tmfs_session_reset(struct tmfs_session *se)
{
	if (se->op.exit)
		se->op.exit(se->data, 0);
	se->exited = 0;
}

int tmfs_session_exited(struct tmfs_session *se)
{
	if (se->op.exited)
		return se->op.exited(se->data);
	else
		return se->exited;
}

void *tmfs_session_data(struct tmfs_session *se)
{
	return se->data;
}

static struct tmfs_chan *tmfs_chan_new_common(struct tmfs_chan_ops *op, int fd,
					      size_t bufsize, void *data,
					      int compat)
{
	struct tmfs_chan *ch = (struct tmfs_chan *) malloc(sizeof(*ch));
	if (ch == NULL) {
		fprintf(stderr, "tmfs: failed to allocate channel\n");
		return NULL;
	}

	memset(ch, 0, sizeof(*ch));
	ch->op = *op;
	ch->fd = fd;
	ch->bufsize = bufsize;
	ch->data = data;
	ch->compat = compat;

	return ch;
}

struct tmfs_chan *tmfs_chan_new(struct tmfs_chan_ops *op, int fd,
				size_t bufsize, void *data)
{
	return tmfs_chan_new_common(op, fd, bufsize, data, 0);
}

struct tmfs_chan *tmfs_chan_new_compat24(struct tmfs_chan_ops_compat24 *op,
					 int fd, size_t bufsize, void *data)
{
	return tmfs_chan_new_common((struct tmfs_chan_ops *) op, fd, bufsize,
				    data, 24);
}

int tmfs_chan_fd(struct tmfs_chan *ch)
{
	return ch->fd;
}

int tmfs_chan_clearfd(struct tmfs_chan *ch)
{
       int fd = ch->fd;
       ch->fd = -1;
       return fd;
}

size_t tmfs_chan_bufsize(struct tmfs_chan *ch)
{
	return ch->bufsize;
}

void *tmfs_chan_data(struct tmfs_chan *ch)
{
	return ch->data;
}

struct tmfs_session *tmfs_chan_session(struct tmfs_chan *ch)
{
	return ch->se;
}

int tmfs_chan_recv(struct tmfs_chan **chp, char *buf, size_t size)
{
	struct tmfs_chan *ch = *chp;
	if (ch->compat)
		return ((struct tmfs_chan_ops_compat24 *) &ch->op)
			->receive(ch, buf, size);
	else
		return ch->op.receive(chp, buf, size);
}

int tmfs_chan_receive(struct tmfs_chan *ch, char *buf, size_t size)
{
	int res;

	res = tmfs_chan_recv(&ch, buf, size);
	return res >= 0 ? res : (res != -EINTR && res != -EAGAIN) ? -1 : 0;
}

int tmfs_chan_send(struct tmfs_chan *ch, const struct iovec iov[], size_t count)
{
	return ch->op.send(ch, iov, count);
}

void tmfs_chan_destroy(struct tmfs_chan *ch)
{
	tmfs_session_remove_chan(ch);
	if (ch->op.destroy)
		ch->op.destroy(ch);
	free(ch);
}

#ifndef __FreeBSD__
TMFS_SYMVER(".symver tmfs_chan_new_compat24,tmfs_chan_new@TMFS_2.4");
#endif
