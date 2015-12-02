/*
  TMFS: Filesystem in Userspace
  Copyright (C) 2001-2007  Miklos Szeredi <miklos@szeredi.hu>

  This program can be distributed under the terms of the GNU GPL.
  See the file COPYING.

  gcc -Wall hello_ll.c `pkg-config tmfs --cflags --libs` -o hello_ll
*/

#define TMFS_USE_VERSION 26

#include <tmfs_lowlevel.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <assert.h>

static const char *hello_str = "Hello World!\n";
static const char *hello_name = "hello";

static int hello_stat(tmfs_ino_t ino, struct stat *stbuf)
{
	stbuf->st_ino = ino;
	switch (ino) {
	case 1:
		stbuf->st_mode = S_IFDIR | 0755;
		stbuf->st_nlink = 2;
		break;

	case 2:
		stbuf->st_mode = S_IFREG | 0444;
		stbuf->st_nlink = 1;
		stbuf->st_size = strlen(hello_str);
		break;

	default:
		return -1;
	}
	return 0;
}

static void hello_ll_getattr(tmfs_req_t req, tmfs_ino_t ino,
			     struct tmfs_file_info *fi)
{
	struct stat stbuf;

	(void) fi;

	memset(&stbuf, 0, sizeof(stbuf));
	if (hello_stat(ino, &stbuf) == -1)
		tmfs_reply_err(req, ENOENT);
	else
		tmfs_reply_attr(req, &stbuf, 1.0);
}

static void hello_ll_lookup(tmfs_req_t req, tmfs_ino_t parent, const char *name)
{
	struct tmfs_entry_param e;

	if (parent != 1 || strcmp(name, hello_name) != 0)
		tmfs_reply_err(req, ENOENT);
	else {
		memset(&e, 0, sizeof(e));
		e.ino = 2;
		e.attr_timeout = 1.0;
		e.entry_timeout = 1.0;
		hello_stat(e.ino, &e.attr);

		tmfs_reply_entry(req, &e);
	}
}

struct dirbuf {
	char *p;
	size_t size;
};

static void dirbuf_add(tmfs_req_t req, struct dirbuf *b, const char *name,
		       tmfs_ino_t ino)
{
	struct stat stbuf;
	size_t oldsize = b->size;
	b->size += tmfs_add_direntry(req, NULL, 0, name, NULL, 0);
	b->p = (char *) realloc(b->p, b->size);
	memset(&stbuf, 0, sizeof(stbuf));
	stbuf.st_ino = ino;
	tmfs_add_direntry(req, b->p + oldsize, b->size - oldsize, name, &stbuf,
			  b->size);
}

#define min(x, y) ((x) < (y) ? (x) : (y))

static int reply_buf_limited(tmfs_req_t req, const char *buf, size_t bufsize,
			     off_t off, size_t maxsize)
{
	if (off < bufsize)
		return tmfs_reply_buf(req, buf + off,
				      min(bufsize - off, maxsize));
	else
		return tmfs_reply_buf(req, NULL, 0);
}

static void hello_ll_readdir(tmfs_req_t req, tmfs_ino_t ino, size_t size,
			     off_t off, struct tmfs_file_info *fi)
{
	(void) fi;

	if (ino != 1)
		tmfs_reply_err(req, ENOTDIR);
	else {
		struct dirbuf b;

		memset(&b, 0, sizeof(b));
		dirbuf_add(req, &b, ".", 1);
		dirbuf_add(req, &b, "..", 1);
		dirbuf_add(req, &b, hello_name, 2);
		reply_buf_limited(req, b.p, b.size, off, size);
		free(b.p);
	}
}

static void hello_ll_open(tmfs_req_t req, tmfs_ino_t ino,
			  struct tmfs_file_info *fi)
{
	if (ino != 2)
		tmfs_reply_err(req, EISDIR);
	else if ((fi->flags & 3) != O_RDONLY)
		tmfs_reply_err(req, EACCES);
	else
		tmfs_reply_open(req, fi);
}

static void hello_ll_read(tmfs_req_t req, tmfs_ino_t ino, size_t size,
			  off_t off, struct tmfs_file_info *fi)
{
	(void) fi;

	assert(ino == 2);
	reply_buf_limited(req, hello_str, strlen(hello_str), off, size);
}

static struct tmfs_lowlevel_ops hello_ll_oper = {
	.lookup		= hello_ll_lookup,
	.getattr	= hello_ll_getattr,
	.readdir	= hello_ll_readdir,
	.open		= hello_ll_open,
	.read		= hello_ll_read,
};

int main(int argc, char *argv[])
{
	struct tmfs_args args = TMFS_ARGS_INIT(argc, argv);
	struct tmfs_chan *ch;
	char *mountpoint;
	int err = -1;

	if (tmfs_parse_cmdline(&args, &mountpoint, NULL, NULL) != -1 &&
	    (ch = tmfs_mount(mountpoint, &args)) != NULL) {
		struct tmfs_session *se;

		se = tmfs_lowlevel_new(&args, &hello_ll_oper,
				       sizeof(hello_ll_oper), NULL);
		if (se != NULL) {
			if (tmfs_set_signal_handlers(se) != -1) {
				tmfs_session_add_chan(se, ch);
				err = tmfs_session_loop(se);
				tmfs_remove_signal_handlers(se);
				tmfs_session_remove_chan(ch);
			}
			tmfs_session_destroy(se);
		}
		tmfs_unmount(mountpoint, ch);
	}
	tmfs_opt_free_args(&args);

	return err ? 1 : 0;
}
