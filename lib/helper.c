/*
  TMFS: Filesystem in Userspace
  Copyright (C) 2001-2007  Miklos Szeredi <miklos@szeredi.hu>

  This program can be distributed under the terms of the GNU LGPLv2.
  See the file COPYING.LIB.
*/

#include "config.h"
#include "tmfs_i.h"
#include "tmfs_misc.h"
#include "tmfs_opt.h"
#include "tmfs_lowlevel.h"
#include "tmfs_common_compat.h"

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <unistd.h>
#include <string.h>
#include <limits.h>
#include <errno.h>
#include <sys/param.h>

enum  {
	KEY_HELP,
	KEY_HELP_NOHEADER,
	KEY_VERSION,
};

struct helper_opts {
	int singlethread;
	int foreground;
	int nodefault_subtype;
	char *mountpoint;
};

#define TMFS_HELPER_OPT(t, p) { t, offsetof(struct helper_opts, p), 1 }

static const struct tmfs_opt tmfs_helper_opts[] = {
	TMFS_HELPER_OPT("-d",		foreground),
	TMFS_HELPER_OPT("debug",	foreground),
	TMFS_HELPER_OPT("-f",		foreground),
	TMFS_HELPER_OPT("-s",		singlethread),
	TMFS_HELPER_OPT("fsname=",	nodefault_subtype),
	TMFS_HELPER_OPT("subtype=",	nodefault_subtype),

	TMFS_OPT_KEY("-h",		KEY_HELP),
	TMFS_OPT_KEY("--help",		KEY_HELP),
	TMFS_OPT_KEY("-ho",		KEY_HELP_NOHEADER),
	TMFS_OPT_KEY("-V",		KEY_VERSION),
	TMFS_OPT_KEY("--version",	KEY_VERSION),
	TMFS_OPT_KEY("-d",		TMFS_OPT_KEY_KEEP),
	TMFS_OPT_KEY("debug",		TMFS_OPT_KEY_KEEP),
	TMFS_OPT_KEY("fsname=",		TMFS_OPT_KEY_KEEP),
	TMFS_OPT_KEY("subtype=",	TMFS_OPT_KEY_KEEP),
	TMFS_OPT_END
};

static void usage(const char *progname)
{
	fprintf(stderr,
		"usage: %s mountpoint [options]\n\n", progname);
	fprintf(stderr,
		"general options:\n"
		"    -o opt,[opt...]        mount options\n"
		"    -h   --help            print help\n"
		"    -V   --version         print version\n"
		"\n");
}

static void helper_help(void)
{
	fprintf(stderr,
		"TMFS options:\n"
		"    -d   -o debug          enable debug output (implies -f)\n"
		"    -f                     foreground operation\n"
		"    -s                     disable multi-threaded operation\n"
		"\n"
		);
}

static void helper_version(void)
{
	fprintf(stderr, "TMFS library version: %s\n", PACKAGE_VERSION);
}

static int tmfs_helper_opt_proc(void *data, const char *arg, int key,
				struct tmfs_args *outargs)
{
	struct helper_opts *hopts = data;

	switch (key) {
	case KEY_HELP:
		usage(outargs->argv[0]);
		/* fall through */

	case KEY_HELP_NOHEADER:
		helper_help();
		return tmfs_opt_add_arg(outargs, "-h");

	case KEY_VERSION:
		helper_version();
		return 1;

	case TMFS_OPT_KEY_NONOPT:
		if (!hopts->mountpoint) {
			char mountpoint[PATH_MAX];
			if (realpath(arg, mountpoint) == NULL) {
				fprintf(stderr,
					"tmfs: bad mount point `%s': %s\n",
					arg, strerror(errno));
				return -1;
			}
			return tmfs_opt_add_opt(&hopts->mountpoint, mountpoint);
		} else {
			fprintf(stderr, "tmfs: invalid argument `%s'\n", arg);
			return -1;
		}

	default:
		return 1;
	}
}

static int add_default_subtype(const char *progname, struct tmfs_args *args)
{
	int res;
	char *subtype_opt;
	const char *basename = strrchr(progname, '/');
	if (basename == NULL)
		basename = progname;
	else if (basename[1] != '\0')
		basename++;

	subtype_opt = (char *) malloc(strlen(basename) + 64);
	if (subtype_opt == NULL) {
		fprintf(stderr, "tmfs: memory allocation failed\n");
		return -1;
	}
	sprintf(subtype_opt, "-osubtype=%s", basename);
	res = tmfs_opt_add_arg(args, subtype_opt);
	free(subtype_opt);
	return res;
}

int tmfs_parse_cmdline(struct tmfs_args *args, char **mountpoint,
		       int *multithreaded, int *foreground)
{
	int res;
	struct helper_opts hopts;

	memset(&hopts, 0, sizeof(hopts));
	res = tmfs_opt_parse(args, &hopts, tmfs_helper_opts,
			     tmfs_helper_opt_proc);
	if (res == -1)
		return -1;

	if (!hopts.nodefault_subtype) {
		res = add_default_subtype(args->argv[0], args);
		if (res == -1)
			goto err;
	}
	if (mountpoint)
		*mountpoint = hopts.mountpoint;
	else
		free(hopts.mountpoint);

	if (multithreaded)
		*multithreaded = !hopts.singlethread;
	if (foreground)
		*foreground = hopts.foreground;
	return 0;

err:
	free(hopts.mountpoint);
	return -1;
}

int tmfs_daemonize(int foreground)
{
	if (!foreground) {
		int nullfd;

		/*
		 * demonize current process by forking it and killing the
		 * parent.  This makes current process as a child of 'init'.
		 */
		switch(fork()) {
		case -1:
			perror("tmfs_daemonize: fork");
			return -1;
		case 0:
			break;
		default:
			_exit(0);
		}

		if (setsid() == -1) {
			perror("tmfs_daemonize: setsid");
			return -1;
		}

		(void) chdir("/");

		nullfd = open("/dev/null", O_RDWR, 0);
		if (nullfd != -1) {
			(void) dup2(nullfd, 0);
			(void) dup2(nullfd, 1);
			(void) dup2(nullfd, 2);
			if (nullfd > 2)
				close(nullfd);
		}
	}
	return 0;
}

static struct tmfs_chan *tmfs_mount_common(const char *mountpoint,
					   struct tmfs_args *args)
{
	struct tmfs_chan *ch;
	int fd;

	/*
	 * Make sure file descriptors 0, 1 and 2 are open, otherwise chaos
	 * would ensue.
	 */
	do {
		fd = open("/dev/null", O_RDWR);
		if (fd > 2)
			close(fd);
	} while (fd >= 0 && fd <= 2);

	fd = tmfs_mount_compat25(mountpoint, args);
	if (fd == -1)
		return NULL;

	ch = tmfs_kern_chan_new(fd);
	if (!ch)
		tmfs_kern_unmount(mountpoint, fd);

	return ch;
}

struct tmfs_chan *tmfs_mount(const char *mountpoint, struct tmfs_args *args)
{
	return tmfs_mount_common(mountpoint, args);
}

static void tmfs_unmount_common(const char *mountpoint, struct tmfs_chan *ch)
{
	if (mountpoint) {
		int fd = ch ? tmfs_chan_clearfd(ch) : -1;
		tmfs_kern_unmount(mountpoint, fd);
		if (ch)
			tmfs_chan_destroy(ch);
	}
}

void tmfs_unmount(const char *mountpoint, struct tmfs_chan *ch)
{
	tmfs_unmount_common(mountpoint, ch);
}

struct tmfs *tmfs_setup_common(int argc, char *argv[],
			       const struct tmfs_operations *op,
			       size_t op_size,
			       char **mountpoint,
			       int *multithreaded,
			       int *fd,
			       void *user_data,
			       int compat)
{
	struct tmfs_args args = TMFS_ARGS_INIT(argc, argv);
	struct tmfs_chan *ch;
	struct tmfs *tmfs;
	int foreground;
	int res;

	res = tmfs_parse_cmdline(&args, mountpoint, multithreaded, &foreground);
	if (res == -1)
		return NULL;

	ch = tmfs_mount_common(*mountpoint, &args);
	if (!ch) {
		tmfs_opt_free_args(&args);
		goto err_free;
	}

	tmfs = tmfs_new_common(ch, &args, op, op_size, user_data, compat);
	tmfs_opt_free_args(&args);
	if (tmfs == NULL)
		goto err_unmount;

	res = tmfs_daemonize(foreground);
	if (res == -1)
		goto err_unmount;

	res = tmfs_set_signal_handlers(tmfs_get_session(tmfs));
	if (res == -1)
		goto err_unmount;

	if (fd)
		*fd = tmfs_chan_fd(ch);

	return tmfs;

err_unmount:
	tmfs_unmount_common(*mountpoint, ch);
	if (tmfs)
		tmfs_destroy(tmfs);
err_free:
	free(*mountpoint);
	return NULL;
}

struct tmfs *tmfs_setup(int argc, char *argv[],
			const struct tmfs_operations *op, size_t op_size,
			char **mountpoint, int *multithreaded, void *user_data)
{
	return tmfs_setup_common(argc, argv, op, op_size, mountpoint,
				 multithreaded, NULL, user_data, 0);
}

static void tmfs_teardown_common(struct tmfs *tmfs, char *mountpoint)
{
	struct tmfs_session *se = tmfs_get_session(tmfs);
	struct tmfs_chan *ch = tmfs_session_next_chan(se, NULL);
	tmfs_remove_signal_handlers(se);
	tmfs_unmount_common(mountpoint, ch);
	tmfs_destroy(tmfs);
	free(mountpoint);
}

void tmfs_teardown(struct tmfs *tmfs, char *mountpoint)
{
	tmfs_teardown_common(tmfs, mountpoint);
}

static int tmfs_main_common(int argc, char *argv[],
			    const struct tmfs_operations *op, size_t op_size,
			    void *user_data, int compat)
{
	struct tmfs *tmfs;
	char *mountpoint;
	int multithreaded;
	int res;

	tmfs = tmfs_setup_common(argc, argv, op, op_size, &mountpoint,
				 &multithreaded, NULL, user_data, compat);
	if (tmfs == NULL)
		return 1;

	if (multithreaded)
		res = tmfs_loop_mt(tmfs);
	else
		res = tmfs_loop(tmfs);

	tmfs_teardown_common(tmfs, mountpoint);
	if (res == -1)
		return 1;

	return 0;
}

int tmfs_main_real(int argc, char *argv[], const struct tmfs_operations *op,
		   size_t op_size, void *user_data)
{
	return tmfs_main_common(argc, argv, op, op_size, user_data, 0);
}

#undef tmfs_main
int tmfs_main(void);
int tmfs_main(void)
{
	fprintf(stderr, "tmfs_main(): This function does not exist\n");
	return -1;
}

int tmfs_version(void)
{
	return TMFS_VERSION;
}

#include "tmfs_compat.h"

#if !defined(__FreeBSD__) && !defined(__NetBSD__)

struct tmfs *tmfs_setup_compat22(int argc, char *argv[],
				 const struct tmfs_operations_compat22 *op,
				 size_t op_size, char **mountpoint,
				 int *multithreaded, int *fd)
{
	return tmfs_setup_common(argc, argv, (struct tmfs_operations *) op,
				 op_size, mountpoint, multithreaded, fd, NULL,
				 22);
}

struct tmfs *tmfs_setup_compat2(int argc, char *argv[],
				const struct tmfs_operations_compat2 *op,
				char **mountpoint, int *multithreaded,
				int *fd)
{
	return tmfs_setup_common(argc, argv, (struct tmfs_operations *) op,
				 sizeof(struct tmfs_operations_compat2),
				 mountpoint, multithreaded, fd, NULL, 21);
}

int tmfs_main_real_compat22(int argc, char *argv[],
			    const struct tmfs_operations_compat22 *op,
			    size_t op_size)
{
	return tmfs_main_common(argc, argv, (struct tmfs_operations *) op,
				op_size, NULL, 22);
}

void tmfs_main_compat1(int argc, char *argv[],
		       const struct tmfs_operations_compat1 *op)
{
	tmfs_main_common(argc, argv, (struct tmfs_operations *) op,
			 sizeof(struct tmfs_operations_compat1), NULL, 11);
}

int tmfs_main_compat2(int argc, char *argv[],
		      const struct tmfs_operations_compat2 *op)
{
	return tmfs_main_common(argc, argv, (struct tmfs_operations *) op,
				sizeof(struct tmfs_operations_compat2), NULL,
				21);
}

int tmfs_mount_compat1(const char *mountpoint, const char *args[])
{
	/* just ignore mount args for now */
	(void) args;
	return tmfs_mount_compat22(mountpoint, NULL);
}

TMFS_SYMVER(".symver tmfs_setup_compat2,__tmfs_setup@");
TMFS_SYMVER(".symver tmfs_setup_compat22,tmfs_setup@TMFS_2.2");
TMFS_SYMVER(".symver tmfs_teardown,__tmfs_teardown@");
TMFS_SYMVER(".symver tmfs_main_compat2,tmfs_main@");
TMFS_SYMVER(".symver tmfs_main_real_compat22,tmfs_main_real@TMFS_2.2");

#endif /* __FreeBSD__ || __NetBSD__ */


struct tmfs *tmfs_setup_compat25(int argc, char *argv[],
				 const struct tmfs_operations_compat25 *op,
				 size_t op_size, char **mountpoint,
				 int *multithreaded, int *fd)
{
	return tmfs_setup_common(argc, argv, (struct tmfs_operations *) op,
				 op_size, mountpoint, multithreaded, fd, NULL,
				 25);
}

int tmfs_main_real_compat25(int argc, char *argv[],
			    const struct tmfs_operations_compat25 *op,
			    size_t op_size)
{
	return tmfs_main_common(argc, argv, (struct tmfs_operations *) op,
				op_size, NULL, 25);
}

void tmfs_teardown_compat22(struct tmfs *tmfs, int fd, char *mountpoint)
{
	(void) fd;
	tmfs_teardown_common(tmfs, mountpoint);
}

int tmfs_mount_compat25(const char *mountpoint, struct tmfs_args *args)
{
	return tmfs_kern_mount(mountpoint, args);
}

TMFS_SYMVER(".symver tmfs_setup_compat25,tmfs_setup@TMFS_2.5");
TMFS_SYMVER(".symver tmfs_teardown_compat22,tmfs_teardown@TMFS_2.2");
TMFS_SYMVER(".symver tmfs_main_real_compat25,tmfs_main_real@TMFS_2.5");
TMFS_SYMVER(".symver tmfs_mount_compat25,tmfs_mount@TMFS_2.5");
