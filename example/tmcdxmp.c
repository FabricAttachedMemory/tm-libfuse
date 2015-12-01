/*
  TMCD example: Character device in Userspace
  Copyright (C) 2008-2009  SUSE Linux Products GmbH
  Copyright (C) 2008-2009  Tejun Heo <tj@kernel.org>

  This program can be distributed under the terms of the GNU GPL.
  See the file COPYING.

  gcc -Wall tmcdxmp.c `pkg-config tmfs --cflags --libs` -o tmcdxmp
*/

#define TMFS_USE_VERSION 29

#include <tmcd_lowlevel.h>
#include <tmfs_opt.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#include "fioc.h"

static void *tmcdxmp_buf;
static size_t tmcdxmp_size;

static const char *usage =
"usage: tmcdxmp [options]\n"
"\n"
"options:\n"
"    --help|-h             print this help message\n"
"    --maj=MAJ|-M MAJ      device major number\n"
"    --min=MIN|-m MIN      device minor number\n"
"    --name=NAME|-n NAME   device name (mandatory)\n"
"\n";

static int tmcdxmp_resize(size_t new_size)
{
	void *new_buf;

	if (new_size == tmcdxmp_size)
		return 0;

	new_buf = realloc(tmcdxmp_buf, new_size);
	if (!new_buf && new_size)
		return -ENOMEM;

	if (new_size > tmcdxmp_size)
		memset(new_buf + tmcdxmp_size, 0, new_size - tmcdxmp_size);

	tmcdxmp_buf = new_buf;
	tmcdxmp_size = new_size;

	return 0;
}

static int tmcdxmp_expand(size_t new_size)
{
	if (new_size > tmcdxmp_size)
		return tmcdxmp_resize(new_size);
	return 0;
}

static void tmcdxmp_open(tmfs_req_t req, struct tmfs_file_info *fi)
{
	tmfs_reply_open(req, fi);
}

static void tmcdxmp_read(tmfs_req_t req, size_t size, off_t off,
			 struct tmfs_file_info *fi)
{
	(void)fi;

	if (off >= tmcdxmp_size)
		off = tmcdxmp_size;
	if (size > tmcdxmp_size - off)
		size = tmcdxmp_size - off;

	tmfs_reply_buf(req, tmcdxmp_buf + off, size);
}

static void tmcdxmp_write(tmfs_req_t req, const char *buf, size_t size,
			  off_t off, struct tmfs_file_info *fi)
{
	(void)fi;

	if (tmcdxmp_expand(off + size)) {
		tmfs_reply_err(req, ENOMEM);
		return;
	}

	memcpy(tmcdxmp_buf + off, buf, size);
	tmfs_reply_write(req, size);
}

static void fioc_do_rw(tmfs_req_t req, void *addr, const void *in_buf,
		       size_t in_bufsz, size_t out_bufsz, int is_read)
{
	const struct fioc_rw_arg *arg;
	struct iovec in_iov[2], out_iov[3], iov[3];
	size_t cur_size;

	/* read in arg */
	in_iov[0].iov_base = addr;
	in_iov[0].iov_len = sizeof(*arg);
	if (!in_bufsz) {
		tmfs_reply_ioctl_retry(req, in_iov, 1, NULL, 0);
		return;
	}
	arg = in_buf;
	in_buf += sizeof(*arg);
	in_bufsz -= sizeof(*arg);

	/* prepare size outputs */
	out_iov[0].iov_base =
		addr + (unsigned long)&(((struct fioc_rw_arg *)0)->prev_size);
	out_iov[0].iov_len = sizeof(arg->prev_size);

	out_iov[1].iov_base =
		addr + (unsigned long)&(((struct fioc_rw_arg *)0)->new_size);
	out_iov[1].iov_len = sizeof(arg->new_size);

	/* prepare client buf */
	if (is_read) {
		out_iov[2].iov_base = arg->buf;
		out_iov[2].iov_len = arg->size;
		if (!out_bufsz) {
			tmfs_reply_ioctl_retry(req, in_iov, 1, out_iov, 3);
			return;
		}
	} else {
		in_iov[1].iov_base = arg->buf;
		in_iov[1].iov_len = arg->size;
		if (arg->size && !in_bufsz) {
			tmfs_reply_ioctl_retry(req, in_iov, 2, out_iov, 2);
			return;
		}
	}

	/* we're all set */
	cur_size = tmcdxmp_size;
	iov[0].iov_base = &cur_size;
	iov[0].iov_len = sizeof(cur_size);

	iov[1].iov_base = &tmcdxmp_size;
	iov[1].iov_len = sizeof(tmcdxmp_size);

	if (is_read) {
		size_t off = arg->offset;
		size_t size = arg->size;

		if (off >= tmcdxmp_size)
			off = tmcdxmp_size;
		if (size > tmcdxmp_size - off)
			size = tmcdxmp_size - off;

		iov[2].iov_base = tmcdxmp_buf + off;
		iov[2].iov_len = size;
		tmfs_reply_ioctl_iov(req, size, iov, 3);
	} else {
		if (tmcdxmp_expand(arg->offset + in_bufsz)) {
			tmfs_reply_err(req, ENOMEM);
			return;
		}

		memcpy(tmcdxmp_buf + arg->offset, in_buf, in_bufsz);
		tmfs_reply_ioctl_iov(req, in_bufsz, iov, 2);
	}
}

static void tmcdxmp_ioctl(tmfs_req_t req, int cmd, void *arg,
			  struct tmfs_file_info *fi, unsigned flags,
			  const void *in_buf, size_t in_bufsz, size_t out_bufsz)
{
	int is_read = 0;

	(void)fi;

	if (flags & TMFS_IOCTL_COMPAT) {
		tmfs_reply_err(req, ENOSYS);
		return;
	}

	switch (cmd) {
	case FIOC_GET_SIZE:
		if (!out_bufsz) {
			struct iovec iov = { arg, sizeof(size_t) };

			tmfs_reply_ioctl_retry(req, NULL, 0, &iov, 1);
		} else
			tmfs_reply_ioctl(req, 0, &tmcdxmp_size,
					 sizeof(tmcdxmp_size));
		break;

	case FIOC_SET_SIZE:
		if (!in_bufsz) {
			struct iovec iov = { arg, sizeof(size_t) };

			tmfs_reply_ioctl_retry(req, &iov, 1, NULL, 0);
		} else {
			tmcdxmp_resize(*(size_t *)in_buf);
			tmfs_reply_ioctl(req, 0, NULL, 0);
		}
		break;

	case FIOC_READ:
		is_read = 1;
	case FIOC_WRITE:
		fioc_do_rw(req, arg, in_buf, in_bufsz, out_bufsz, is_read);
		break;

	default:
		tmfs_reply_err(req, EINVAL);
	}
}

struct tmcdxmp_param {
	unsigned		major;
	unsigned		minor;
	char			*dev_name;
	int			is_help;
};

#define TMCDXMP_OPT(t, p) { t, offsetof(struct tmcdxmp_param, p), 1 }

static const struct tmfs_opt tmcdxmp_opts[] = {
	TMCDXMP_OPT("-M %u",		major),
	TMCDXMP_OPT("--maj=%u",		major),
	TMCDXMP_OPT("-m %u",		minor),
	TMCDXMP_OPT("--min=%u",		minor),
	TMCDXMP_OPT("-n %s",		dev_name),
	TMCDXMP_OPT("--name=%s",	dev_name),
	TMFS_OPT_KEY("-h",		0),
	TMFS_OPT_KEY("--help",		0),
	TMFS_OPT_END
};

static int tmcdxmp_process_arg(void *data, const char *arg, int key,
			       struct tmfs_args *outargs)
{
	struct tmcdxmp_param *param = data;

	(void)outargs;
	(void)arg;

	switch (key) {
	case 0:
		param->is_help = 1;
		fprintf(stderr, "%s", usage);
		return tmfs_opt_add_arg(outargs, "-ho");
	default:
		return 1;
	}
}

static const struct tmcd_lowlevel_ops tmcdxmp_clop = {
	.open		= tmcdxmp_open,
	.read		= tmcdxmp_read,
	.write		= tmcdxmp_write,
	.ioctl		= tmcdxmp_ioctl,
};

int main(int argc, char **argv)
{
	struct tmfs_args args = TMFS_ARGS_INIT(argc, argv);
	struct tmcdxmp_param param = { 0, 0, NULL, 0 };
	char dev_name[128] = "DEVNAME=";
	const char *dev_info_argv[] = { dev_name };
	struct tmcd_info ci;

	if (tmfs_opt_parse(&args, &param, tmcdxmp_opts, tmcdxmp_process_arg)) {
		printf("failed to parse option\n");
		return 1;
	}

	if (!param.is_help) {
		if (!param.dev_name) {
			fprintf(stderr, "Error: device name missing\n");
			return 1;
		}
		strncat(dev_name, param.dev_name, sizeof(dev_name) - 9);
	}

	memset(&ci, 0, sizeof(ci));
	ci.dev_major = param.major;
	ci.dev_minor = param.minor;
	ci.dev_info_argc = 1;
	ci.dev_info_argv = dev_info_argv;
	ci.flags = TMCD_UNRESTRICTED_IOCTL;

	return tmcd_lowlevel_main(args.argc, args.argv, &ci, &tmcdxmp_clop,
				  NULL);
}
