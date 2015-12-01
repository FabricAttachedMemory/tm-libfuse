/*
  TMCD: Character device in Userspace
  Copyright (C) 2008       SUSE Linux Products GmbH
  Copyright (C) 2008       Tejun Heo <teheo@suse.de>

  This program can be distributed under the terms of the GNU LGPLv2.
  See the file COPYING.LIB.
*/

#include "tmcd_lowlevel.h"
#include "tmfs_kernel.h"
#include "tmfs_i.h"
#include "tmfs_opt.h"
#include "tmfs_misc.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stddef.h>
#include <errno.h>
#include <unistd.h>

struct tmcd_data {
	struct tmcd_lowlevel_ops	clop;
	unsigned			max_read;
	unsigned			dev_major;
	unsigned			dev_minor;
	unsigned			flags;
	unsigned			dev_info_len;
	char				dev_info[];
};

static struct tmcd_lowlevel_ops *req_clop(tmfs_req_t req)
{
	return &req->f->tmcd_data->clop;
}

static void tmcd_fll_open(tmfs_req_t req, tmfs_ino_t ino,
			  struct tmfs_file_info *fi)
{
	(void)ino;
	req_clop(req)->open(req, fi);
}

static void tmcd_fll_read(tmfs_req_t req, tmfs_ino_t ino, size_t size,
			  off_t off, struct tmfs_file_info *fi)
{
	(void)ino;
	req_clop(req)->read(req, size, off, fi);
}

static void tmcd_fll_write(tmfs_req_t req, tmfs_ino_t ino, const char *buf,
			   size_t size, off_t off, struct tmfs_file_info *fi)
{
	(void)ino;
	req_clop(req)->write(req, buf, size, off, fi);
}

static void tmcd_fll_flush(tmfs_req_t req, tmfs_ino_t ino,
			   struct tmfs_file_info *fi)
{
	(void)ino;
	req_clop(req)->flush(req, fi);
}

static void tmcd_fll_release(tmfs_req_t req, tmfs_ino_t ino,
			     struct tmfs_file_info *fi)
{
	(void)ino;
	req_clop(req)->release(req, fi);
}

static void tmcd_fll_fsync(tmfs_req_t req, tmfs_ino_t ino, int datasync,
			   struct tmfs_file_info *fi)
{
	(void)ino;
	req_clop(req)->fsync(req, datasync, fi);
}

static void tmcd_fll_ioctl(tmfs_req_t req, tmfs_ino_t ino, int cmd, void *arg,
		       struct tmfs_file_info *fi, unsigned int flags,
		       const void *in_buf, size_t in_bufsz, size_t out_bufsz)
{
	(void)ino;
	req_clop(req)->ioctl(req, cmd, arg, fi, flags, in_buf, in_bufsz,
			     out_bufsz);
}

static void tmcd_fll_poll(tmfs_req_t req, tmfs_ino_t ino,
			  struct tmfs_file_info *fi, struct tmfs_pollhandle *ph)
{
	(void)ino;
	req_clop(req)->poll(req, fi, ph);
}

static size_t tmcd_pack_info(int argc, const char **argv, char *buf)
{
	size_t size = 0;
	int i;

	for (i = 0; i < argc; i++) {
		size_t len;

		len = strlen(argv[i]) + 1;
		size += len;
		if (buf) {
			memcpy(buf, argv[i], len);
			buf += len;
		}
	}

	return size;
}

static struct tmcd_data *tmcd_prep_data(const struct tmcd_info *ci,
					const struct tmcd_lowlevel_ops *clop)
{
	struct tmcd_data *cd;
	size_t dev_info_len;

	dev_info_len = tmcd_pack_info(ci->dev_info_argc, ci->dev_info_argv,
				      NULL);

	if (dev_info_len > TMCD_INIT_INFO_MAX) {
		fprintf(stderr, "tmcd: dev_info (%zu) too large, limit=%u\n",
			dev_info_len, TMCD_INIT_INFO_MAX);
		return NULL;
	}

	cd = calloc(1, sizeof(*cd) + dev_info_len);
	if (!cd) {
		fprintf(stderr, "tmcd: failed to allocate tmcd_data\n");
		return NULL;
	}

	memcpy(&cd->clop, clop, sizeof(cd->clop));
	cd->max_read = 131072;
	cd->dev_major = ci->dev_major;
	cd->dev_minor = ci->dev_minor;
	cd->dev_info_len = dev_info_len;
	cd->flags = ci->flags;
	tmcd_pack_info(ci->dev_info_argc, ci->dev_info_argv, cd->dev_info);

	return cd;
}

struct tmfs_session *tmcd_lowlevel_new(struct tmfs_args *args,
				       const struct tmcd_info *ci,
				       const struct tmcd_lowlevel_ops *clop,
				       void *userdata)
{
	struct tmfs_lowlevel_ops lop;
	struct tmcd_data *cd;
	struct tmfs_session *se;
	struct tmfs_ll *ll;

	cd = tmcd_prep_data(ci, clop);
	if (!cd)
		return NULL;

	memset(&lop, 0, sizeof(lop));
	lop.init	= clop->init;
	lop.destroy	= clop->destroy;
	lop.open	= clop->open		? tmcd_fll_open		: NULL;
	lop.read	= clop->read		? tmcd_fll_read		: NULL;
	lop.write	= clop->write		? tmcd_fll_write	: NULL;
	lop.flush	= clop->flush		? tmcd_fll_flush	: NULL;
	lop.release	= clop->release		? tmcd_fll_release	: NULL;
	lop.fsync	= clop->fsync		? tmcd_fll_fsync	: NULL;
	lop.ioctl	= clop->ioctl		? tmcd_fll_ioctl	: NULL;
	lop.poll	= clop->poll		? tmcd_fll_poll		: NULL;

	se = tmfs_lowlevel_new_common(args, &lop, sizeof(lop), userdata);
	if (!se) {
		free(cd);
		return NULL;
	}
	ll = se->data;
	ll->tmcd_data = cd;

	return se;
}

static int tmcd_reply_init(tmfs_req_t req, struct tmcd_init_out *arg,
			   char *dev_info, unsigned dev_info_len)
{
	struct iovec iov[3];

	iov[1].iov_base = arg;
	iov[1].iov_len = sizeof(struct tmcd_init_out);
	iov[2].iov_base = dev_info;
	iov[2].iov_len = dev_info_len;

	return tmfs_send_reply_iov_nofree(req, 0, iov, 3);
}

void tmcd_lowlevel_init(tmfs_req_t req, tmfs_ino_t nodeid, const void *inarg)
{
	struct tmfs_init_in *arg = (struct tmfs_init_in *) inarg;
	struct tmcd_init_out outarg;
	struct tmfs_ll *f = req->f;
	struct tmcd_data *cd = f->tmcd_data;
	size_t bufsize = tmfs_chan_bufsize(req->ch);
	struct tmcd_lowlevel_ops *clop = req_clop(req);

	(void) nodeid;
	if (f->debug) {
		fprintf(stderr, "TMCD_INIT: %u.%u\n", arg->major, arg->minor);
		fprintf(stderr, "flags=0x%08x\n", arg->flags);
	}
	f->conn.proto_major = arg->major;
	f->conn.proto_minor = arg->minor;
	f->conn.capable = 0;
	f->conn.want = 0;

	if (arg->major < 7) {
		fprintf(stderr, "tmcd: unsupported protocol version: %u.%u\n",
			arg->major, arg->minor);
		tmfs_reply_err(req, EPROTO);
		return;
	}

	if (bufsize < TMFS_MIN_READ_BUFFER) {
		fprintf(stderr, "tmcd: warning: buffer size too small: %zu\n",
			bufsize);
		bufsize = TMFS_MIN_READ_BUFFER;
	}

	bufsize -= 4096;
	if (bufsize < f->conn.max_write)
		f->conn.max_write = bufsize;

	f->got_init = 1;
	if (f->op.init)
		f->op.init(f->userdata, &f->conn);

	memset(&outarg, 0, sizeof(outarg));
	outarg.major = TMFS_KERNEL_VERSION;
	outarg.minor = TMFS_KERNEL_MINOR_VERSION;
	outarg.flags = cd->flags;
	outarg.max_read = cd->max_read;
	outarg.max_write = f->conn.max_write;
	outarg.dev_major = cd->dev_major;
	outarg.dev_minor = cd->dev_minor;

	if (f->debug) {
		fprintf(stderr, "   TMCD_INIT: %u.%u\n",
			outarg.major, outarg.minor);
		fprintf(stderr, "   flags=0x%08x\n", outarg.flags);
		fprintf(stderr, "   max_read=0x%08x\n", outarg.max_read);
		fprintf(stderr, "   max_write=0x%08x\n", outarg.max_write);
		fprintf(stderr, "   dev_major=%u\n", outarg.dev_major);
		fprintf(stderr, "   dev_minor=%u\n", outarg.dev_minor);
		fprintf(stderr, "   dev_info: %.*s\n", cd->dev_info_len,
			cd->dev_info);
	}

	tmcd_reply_init(req, &outarg, cd->dev_info, cd->dev_info_len);

	if (clop->init_done)
		clop->init_done(f->userdata);

	tmfs_free_req(req);
}

struct tmfs_session *tmcd_lowlevel_setup(int argc, char *argv[],
					 const struct tmcd_info *ci,
					 const struct tmcd_lowlevel_ops *clop,
					 int *multithreaded, void *userdata)
{
	const char *devname = "/dev/tmcd";
	static const struct tmfs_opt kill_subtype_opts[] = {
		TMFS_OPT_KEY("subtype=",  TMFS_OPT_KEY_DISCARD),
		TMFS_OPT_END
	};
	struct tmfs_args args = TMFS_ARGS_INIT(argc, argv);
	struct tmfs_session *se;
	struct tmfs_chan *ch;
	int fd;
	int foreground;
	int res;

	res = tmfs_parse_cmdline(&args, NULL, multithreaded, &foreground);
	if (res == -1)
		goto err_args;

	res = tmfs_opt_parse(&args, NULL, kill_subtype_opts, NULL);
	if (res == -1)
		goto err_args;

	/*
	 * Make sure file descriptors 0, 1 and 2 are open, otherwise chaos
	 * would ensue.
	 */
	do {
		fd = open("/dev/null", O_RDWR);
		if (fd > 2)
			close(fd);
	} while (fd >= 0 && fd <= 2);

	se = tmcd_lowlevel_new(&args, ci, clop, userdata);
	tmfs_opt_free_args(&args);
	if (se == NULL)
		goto err_args;

	fd = open(devname, O_RDWR);
	if (fd == -1) {
		if (errno == ENODEV || errno == ENOENT)
			fprintf(stderr, "tmcd: device not found, try 'modprobe tmcd' first\n");
		else
			fprintf(stderr, "tmcd: failed to open %s: %s\n",
				devname, strerror(errno));
		goto err_se;
	}

	ch = tmfs_kern_chan_new(fd);
	if (!ch) {
		close(fd);
		goto err_se;
	}

	tmfs_session_add_chan(se, ch);

	res = tmfs_set_signal_handlers(se);
	if (res == -1)
		goto err_se;

	res = tmfs_daemonize(foreground);
	if (res == -1)
		goto err_sig;

	return se;

err_sig:
	tmfs_remove_signal_handlers(se);
err_se:
	tmfs_session_destroy(se);
err_args:
	tmfs_opt_free_args(&args);
	return NULL;
}

void tmcd_lowlevel_teardown(struct tmfs_session *se)
{
	tmfs_remove_signal_handlers(se);
	tmfs_session_destroy(se);
}

int tmcd_lowlevel_main(int argc, char *argv[], const struct tmcd_info *ci,
		       const struct tmcd_lowlevel_ops *clop, void *userdata)
{
	struct tmfs_session *se;
	int multithreaded;
	int res;

	se = tmcd_lowlevel_setup(argc, argv, ci, clop, &multithreaded,
				 userdata);
	if (se == NULL)
		return 1;

	if (multithreaded)
		res = tmfs_session_loop_mt(se);
	else
		res = tmfs_session_loop(se);

	tmcd_lowlevel_teardown(se);
	if (res == -1)
		return 1;

	return 0;
}
