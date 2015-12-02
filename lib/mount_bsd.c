/*
  TMFS: Filesystem in Userspace
  Copyright (C) 2005-2008 Csaba Henk <csaba.henk@creo.hu>

  This program can be distributed under the terms of the GNU LGPLv2.
  See the file COPYING.LIB.
*/

#include "tmfs_i.h"
#include "tmfs_misc.h"
#include "tmfs_opt.h"

#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/sysctl.h>
#include <sys/user.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stddef.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <paths.h>
#include <limits.h>

#define TMFSRMOUNT_PROG		"mount_tmfsfs"
#define TMFS_DEV_TRUNK		"/dev/tmfs"

enum {
	KEY_ALLOW_ROOT,
	KEY_RO,
	KEY_HELP,
	KEY_VERSION,
	KEY_KERN
};

struct mount_opts {
	int allow_other;
	int allow_root;
	int ishelp;
	char *kernel_opts;
};

#define TMFS_DUAL_OPT_KEY(templ, key) 				\
	TMFS_OPT_KEY(templ, key), TMFS_OPT_KEY("no" templ, key)

static const struct tmfs_opt tmfs_mount_opts[] = {
	{ "allow_other", offsetof(struct mount_opts, allow_other), 1 },
	{ "allow_root", offsetof(struct mount_opts, allow_root), 1 },
	TMFS_OPT_KEY("allow_root",		KEY_ALLOW_ROOT),
	TMFS_OPT_KEY("-r",			KEY_RO),
	TMFS_OPT_KEY("-h",			KEY_HELP),
	TMFS_OPT_KEY("--help",			KEY_HELP),
	TMFS_OPT_KEY("-V",			KEY_VERSION),
	TMFS_OPT_KEY("--version",		KEY_VERSION),
	/* standard FreeBSD mount options */
	TMFS_DUAL_OPT_KEY("dev",		KEY_KERN),
	TMFS_DUAL_OPT_KEY("async",		KEY_KERN),
	TMFS_DUAL_OPT_KEY("atime",		KEY_KERN),
	TMFS_DUAL_OPT_KEY("dev",		KEY_KERN),
	TMFS_DUAL_OPT_KEY("exec",		KEY_KERN),
	TMFS_DUAL_OPT_KEY("suid",		KEY_KERN),
	TMFS_DUAL_OPT_KEY("symfollow",		KEY_KERN),
	TMFS_DUAL_OPT_KEY("rdonly",		KEY_KERN),
	TMFS_DUAL_OPT_KEY("sync",		KEY_KERN),
	TMFS_DUAL_OPT_KEY("union",		KEY_KERN),
	TMFS_DUAL_OPT_KEY("userquota",		KEY_KERN),
	TMFS_DUAL_OPT_KEY("groupquota",		KEY_KERN),
	TMFS_DUAL_OPT_KEY("clusterr",		KEY_KERN),
	TMFS_DUAL_OPT_KEY("clusterw",		KEY_KERN),
	TMFS_DUAL_OPT_KEY("suiddir",		KEY_KERN),
	TMFS_DUAL_OPT_KEY("snapshot",		KEY_KERN),
	TMFS_DUAL_OPT_KEY("multilabel",		KEY_KERN),
	TMFS_DUAL_OPT_KEY("acls",		KEY_KERN),
	TMFS_DUAL_OPT_KEY("force",		KEY_KERN),
	TMFS_DUAL_OPT_KEY("update",		KEY_KERN),
	TMFS_DUAL_OPT_KEY("ro",			KEY_KERN),
	TMFS_DUAL_OPT_KEY("rw",			KEY_KERN),
	TMFS_DUAL_OPT_KEY("auto",		KEY_KERN),
	/* options supported under both Linux and FBSD */
	TMFS_DUAL_OPT_KEY("allow_other",	KEY_KERN),
	TMFS_DUAL_OPT_KEY("default_permissions",KEY_KERN),
	TMFS_OPT_KEY("max_read=",		KEY_KERN),
	TMFS_OPT_KEY("subtype=",		KEY_KERN),
	/* FBSD TMFS specific mount options */
	TMFS_DUAL_OPT_KEY("private",		KEY_KERN),
	TMFS_DUAL_OPT_KEY("neglect_shares",	KEY_KERN),
	TMFS_DUAL_OPT_KEY("push_symlinks_in",	KEY_KERN),
	TMFS_OPT_KEY("nosync_unmount",		KEY_KERN),
	/* stock FBSD mountopt parsing routine lets anything be negated... */
	/*
	 * Linux specific mount options, but let just the mount util
	 * handle them
	 */
	TMFS_OPT_KEY("fsname=",			KEY_KERN),
	TMFS_OPT_KEY("nonempty",		KEY_KERN),
	TMFS_OPT_KEY("large_read",		KEY_KERN),
	TMFS_OPT_END
};

static void mount_help(void)
{
	fprintf(stderr,
		"    -o allow_root          allow access to root\n"
		);
	system(TMFSRMOUNT_PROG " --help");
	fputc('\n', stderr);
}

static void mount_version(void)
{
	system(TMFSRMOUNT_PROG " --version");
}

static int tmfs_mount_opt_proc(void *data, const char *arg, int key,
			       struct tmfs_args *outargs)
{
	struct mount_opts *mo = data;

	switch (key) {
	case KEY_ALLOW_ROOT:
		if (tmfs_opt_add_opt(&mo->kernel_opts, "allow_other") == -1 ||
		    tmfs_opt_add_arg(outargs, "-oallow_root") == -1)
			return -1;
		return 0;

	case KEY_RO:
		arg = "ro";
		/* fall through */

	case KEY_KERN:
		return tmfs_opt_add_opt(&mo->kernel_opts, arg);

	case KEY_HELP:
		mount_help();
		mo->ishelp = 1;
		break;

	case KEY_VERSION:
		mount_version();
		mo->ishelp = 1;
		break;
	}
	return 1;
}

void tmfs_unmount_compat22(const char *mountpoint)
{
	char dev[128];
	char *ssc, *umount_cmd;
	FILE *sf;
	int rv;
	char seekscript[] =
		/* error message is annoying in help output */
		"exec 2>/dev/null; "
		"/usr/bin/fstat " TMFS_DEV_TRUNK "* | "
		"/usr/bin/awk 'BEGIN{ getline; if (! ($3 == \"PID\" && $10 == \"NAME\")) exit 1; }; "
		"              { if ($3 == %d) print $10; }' | "
		"/usr/bin/sort | "
		"/usr/bin/uniq | "
		"/usr/bin/awk '{ i += 1; if (i > 1){ exit 1; }; printf; }; END{ if (i == 0) exit 1; }'";

	(void) mountpoint;

	/*
	 * If we don't know the fd, we have to resort to the scripted
	 * solution -- iterating over the fd-s is unpractical, as we
	 * don't know how many of open files we have. (This could be
	 * looked up in procfs -- however, that's optional on FBSD; or
	 * read out from the kmem -- however, that's bound to
	 * privileges (in fact, that's what happens when we call the
	 * setgid kmem fstat(1) utility).
	 */
	if (asprintf(&ssc, seekscript, getpid()) == -1)
		return;

	errno = 0;
	sf = popen(ssc, "r");
	free(ssc);
	if (! sf)
		return;

	fgets(dev, sizeof(dev), sf);
	rv = pclose(sf);
	if (rv)
		return;

	if (asprintf(&umount_cmd, "/sbin/umount %s", dev) == -1)
		return;
	system(umount_cmd);
	free(umount_cmd);
}

static void do_unmount(char *dev, int fd)
{
	char device_path[SPECNAMELEN + 12];
	const char *argv[4];
	const char umount_cmd[] = "/sbin/umount";
	pid_t pid;

	snprintf(device_path, SPECNAMELEN + 12, _PATH_DEV "%s", dev);

	argv[0] = umount_cmd;
	argv[1] = "-f";
	argv[2] = device_path;
	argv[3] = NULL;

	pid = fork();

	if (pid == -1)
		return;

	if (pid == 0) {
		close(fd);
		execvp(umount_cmd, (char **)argv);
		exit(1);
	}

	waitpid(pid, NULL, 0);
}

void tmfs_kern_unmount(const char *mountpoint, int fd)
{
	char *ep, dev[128];
	struct stat sbuf;

	(void)mountpoint;

	if (fstat(fd, &sbuf) == -1)
		goto out;

	devname_r(sbuf.st_rdev, S_IFCHR, dev, 128);

	if (strncmp(dev, "tmfs", 4))
		goto out;

	strtol(dev + 4, &ep, 10);
	if (*ep != '\0')
		goto out;

	do_unmount(dev, fd);

out:
	close(fd);
}

/* Check if kernel is doing init in background */
static int init_backgrounded(void)
{
	unsigned ibg, len;

	len = sizeof(ibg);

	if (sysctlbyname("vfs.tmfs.init_backgrounded", &ibg, &len, NULL, 0))
		return 0;

	return ibg;
}


static int tmfs_mount_core(const char *mountpoint, const char *opts)
{
	const char *mountprog = TMFSRMOUNT_PROG;
	int fd;
	char *fdnam, *dev;
	pid_t pid, cpid;
	int status;

	fdnam = getenv("TMFS_DEV_FD");

	if (fdnam) {
		char *ep;

		fd = strtol(fdnam, &ep, 10);

		if (*ep != '\0') {
			fprintf(stderr, "invalid value given in TMFS_DEV_FD\n");
			return -1;
		}

		if (fd < 0)
			return -1;

		goto mount;
	}

	dev = getenv("TMFS_DEV_NAME");

	if (! dev)
		dev = (char *)TMFS_DEV_TRUNK;

	if ((fd = open(dev, O_RDWR)) < 0) {
		perror("tmfs: failed to open tmfs device");
		return -1;
	}

mount:
	if (getenv("TMFS_NO_MOUNT") || ! mountpoint)
		goto out;

	pid = fork();
	cpid = pid;

	if (pid == -1) {
		perror("tmfs: fork() failed");
		close(fd);
		return -1;
	}

	if (pid == 0) {
		if (! init_backgrounded()) {
			/*
			 * If init is not backgrounded, we have to
			 * call the mount util backgrounded, to avoid
			 * deadlock.
			 */

			pid = fork();

			if (pid == -1) {
				perror("tmfs: fork() failed");
				close(fd);
				exit(1);
			}
		}

		if (pid == 0) {
			const char *argv[32];
			int a = 0;

			if (! fdnam && asprintf(&fdnam, "%d", fd) == -1) {
				perror("tmfs: failed to assemble mount arguments");
				exit(1);
			}

			argv[a++] = mountprog;
			if (opts) {
				argv[a++] = "-o";
				argv[a++] = opts;
			}
			argv[a++] = fdnam;
			argv[a++] = mountpoint;
			argv[a++] = NULL;
			execvp(mountprog, (char **) argv);
			perror("tmfs: failed to exec mount program");
			exit(1);
		}

		exit(0);
	}

	if (waitpid(cpid, &status, 0) == -1 || WEXITSTATUS(status) != 0) {
		perror("tmfs: failed to mount file system");
		close(fd);
		return -1;
	}

out:
	return fd;
}

int tmfs_kern_mount(const char *mountpoint, struct tmfs_args *args)
{
	struct mount_opts mo;
	int res = -1;

	memset(&mo, 0, sizeof(mo));
	/* mount util should not try to spawn the daemon */
	setenv("MOUNT_TMFSFS_SAFE", "1", 1);
	/* to notify the mount util it's called from lib */
	setenv("MOUNT_TMFSFS_CALL_BY_LIB", "1", 1);

	if (args &&
	    tmfs_opt_parse(args, &mo, tmfs_mount_opts, tmfs_mount_opt_proc) == -1)
		return -1;

	if (mo.allow_other && mo.allow_root) {
		fprintf(stderr, "tmfs: 'allow_other' and 'allow_root' options are mutually exclusive\n");
		goto out;
	}
	if (mo.ishelp)
		return 0;

	res = tmfs_mount_core(mountpoint, mo.kernel_opts);
out:
	free(mo.kernel_opts);
	return res;
}

TMFS_SYMVER(".symver tmfs_unmount_compat22,tmfs_unmount@TMFS_2.2");
