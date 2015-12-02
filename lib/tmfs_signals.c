/*
  TMFS: Filesystem in Userspace
  Copyright (C) 2001-2007  Miklos Szeredi <miklos@szeredi.hu>

  This program can be distributed under the terms of the GNU LGPLv2.
  See the file COPYING.LIB
*/

#include "tmfs_lowlevel.h"

#include <stdio.h>
#include <string.h>
#include <signal.h>

static struct tmfs_session *tmfs_instance;

static void exit_handler(int sig)
{
	(void) sig;
	if (tmfs_instance)
		tmfs_session_exit(tmfs_instance);
}

static int set_one_signal_handler(int sig, void (*handler)(int), int remove)
{
	struct sigaction sa;
	struct sigaction old_sa;

	memset(&sa, 0, sizeof(struct sigaction));
	sa.sa_handler = remove ? SIG_DFL : handler;
	sigemptyset(&(sa.sa_mask));
	sa.sa_flags = 0;

	if (sigaction(sig, NULL, &old_sa) == -1) {
		perror("tmfs: cannot get old signal handler");
		return -1;
	}

	if (old_sa.sa_handler == (remove ? handler : SIG_DFL) &&
	    sigaction(sig, &sa, NULL) == -1) {
		perror("tmfs: cannot set signal handler");
		return -1;
	}
	return 0;
}

int tmfs_set_signal_handlers(struct tmfs_session *se)
{
	if (set_one_signal_handler(SIGHUP, exit_handler, 0) == -1 ||
	    set_one_signal_handler(SIGINT, exit_handler, 0) == -1 ||
	    set_one_signal_handler(SIGTERM, exit_handler, 0) == -1 ||
	    set_one_signal_handler(SIGPIPE, SIG_IGN, 0) == -1)
		return -1;

	tmfs_instance = se;
	return 0;
}

void tmfs_remove_signal_handlers(struct tmfs_session *se)
{
	if (tmfs_instance != se)
		fprintf(stderr,
			"tmfs: tmfs_remove_signal_handlers: unknown session\n");
	else
		tmfs_instance = NULL;

	set_one_signal_handler(SIGHUP, exit_handler, 1);
	set_one_signal_handler(SIGINT, exit_handler, 1);
	set_one_signal_handler(SIGTERM, exit_handler, 1);
	set_one_signal_handler(SIGPIPE, SIG_IGN, 1);
}

