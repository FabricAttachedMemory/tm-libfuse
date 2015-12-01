/*
  TMFS: Filesystem in Userspace
  Copyright (C) 2001-2007  Miklos Szeredi <miklos@szeredi.hu>

  This program can be distributed under the terms of the GNU LGPLv2.
  See the file COPYING.LIB.
*/

#include "tmfs_lowlevel.h"
#include "tmfs_misc.h"
#include "tmfs_kernel.h"
#include "tmfs_i.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <semaphore.h>
#include <errno.h>
#include <sys/time.h>

/* Environment var controlling the thread stack size */
#define ENVNAME_THREAD_STACK "TMFS_THREAD_STACK"

struct tmfs_worker {
	struct tmfs_worker *prev;
	struct tmfs_worker *next;
	pthread_t thread_id;
	size_t bufsize;
	char *buf;
	struct tmfs_mt *mt;
};

struct tmfs_mt {
	pthread_mutex_t lock;
	int numworker;
	int numavail;
	struct tmfs_session *se;
	struct tmfs_chan *prevch;
	struct tmfs_worker main;
	sem_t finish;
	int exit;
	int error;
};

static void list_add_worker(struct tmfs_worker *w, struct tmfs_worker *next)
{
	struct tmfs_worker *prev = next->prev;
	w->next = next;
	w->prev = prev;
	prev->next = w;
	next->prev = w;
}

static void list_del_worker(struct tmfs_worker *w)
{
	struct tmfs_worker *prev = w->prev;
	struct tmfs_worker *next = w->next;
	prev->next = next;
	next->prev = prev;
}

static int tmfs_loop_start_thread(struct tmfs_mt *mt);

static void *tmfs_do_work(void *data)
{
	struct tmfs_worker *w = (struct tmfs_worker *) data;
	struct tmfs_mt *mt = w->mt;

	while (!tmfs_session_exited(mt->se)) {
		int isforget = 0;
		struct tmfs_chan *ch = mt->prevch;
		struct tmfs_buf fbuf = {
			.mem = w->buf,
			.size = w->bufsize,
		};
		int res;

		pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
		res = tmfs_session_receive_buf(mt->se, &fbuf, &ch);
		pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL);
		if (res == -EINTR)
			continue;
		if (res <= 0) {
			if (res < 0) {
				tmfs_session_exit(mt->se);
				mt->error = -1;
			}
			break;
		}

		pthread_mutex_lock(&mt->lock);
		if (mt->exit) {
			pthread_mutex_unlock(&mt->lock);
			return NULL;
		}

		/*
		 * This disgusting hack is needed so that zillions of threads
		 * are not created on a burst of FORGET messages
		 */
		if (!(fbuf.flags & TMFS_BUF_IS_FD)) {
			struct tmfs_in_header *in = fbuf.mem;

			if (in->opcode == TMFS_FORGET ||
			    in->opcode == TMFS_BATCH_FORGET)
				isforget = 1;
		}

		if (!isforget)
			mt->numavail--;
		if (mt->numavail == 0)
			tmfs_loop_start_thread(mt);
		pthread_mutex_unlock(&mt->lock);

		tmfs_session_process_buf(mt->se, &fbuf, ch);

		pthread_mutex_lock(&mt->lock);
		if (!isforget)
			mt->numavail++;
		if (mt->numavail > 10) {
			if (mt->exit) {
				pthread_mutex_unlock(&mt->lock);
				return NULL;
			}
			list_del_worker(w);
			mt->numavail--;
			mt->numworker--;
			pthread_mutex_unlock(&mt->lock);

			pthread_detach(w->thread_id);
			free(w->buf);
			free(w);
			return NULL;
		}
		pthread_mutex_unlock(&mt->lock);
	}

	sem_post(&mt->finish);

	return NULL;
}

int tmfs_start_thread(pthread_t *thread_id, void *(*func)(void *), void *arg)
{
	sigset_t oldset;
	sigset_t newset;
	int res;
	pthread_attr_t attr;
	char *stack_size;

	/* Override default stack size */
	pthread_attr_init(&attr);
	stack_size = getenv(ENVNAME_THREAD_STACK);
	if (stack_size && pthread_attr_setstacksize(&attr, atoi(stack_size)))
		fprintf(stderr, "tmfs: invalid stack size: %s\n", stack_size);

	/* Disallow signal reception in worker threads */
	sigemptyset(&newset);
	sigaddset(&newset, SIGTERM);
	sigaddset(&newset, SIGINT);
	sigaddset(&newset, SIGHUP);
	sigaddset(&newset, SIGQUIT);
	pthread_sigmask(SIG_BLOCK, &newset, &oldset);
	res = pthread_create(thread_id, &attr, func, arg);
	pthread_sigmask(SIG_SETMASK, &oldset, NULL);
	pthread_attr_destroy(&attr);
	if (res != 0) {
		fprintf(stderr, "tmfs: error creating thread: %s\n",
			strerror(res));
		return -1;
	}

	return 0;
}

static int tmfs_loop_start_thread(struct tmfs_mt *mt)
{
	int res;
	struct tmfs_worker *w = malloc(sizeof(struct tmfs_worker));
	if (!w) {
		fprintf(stderr, "tmfs: failed to allocate worker structure\n");
		return -1;
	}
	memset(w, 0, sizeof(struct tmfs_worker));
	w->bufsize = tmfs_chan_bufsize(mt->prevch);
	w->buf = malloc(w->bufsize);
	w->mt = mt;
	if (!w->buf) {
		fprintf(stderr, "tmfs: failed to allocate read buffer\n");
		free(w);
		return -1;
	}

	res = tmfs_start_thread(&w->thread_id, tmfs_do_work, w);
	if (res == -1) {
		free(w->buf);
		free(w);
		return -1;
	}
	list_add_worker(w, &mt->main);
	mt->numavail ++;
	mt->numworker ++;

	return 0;
}

static void tmfs_join_worker(struct tmfs_mt *mt, struct tmfs_worker *w)
{
	pthread_join(w->thread_id, NULL);
	pthread_mutex_lock(&mt->lock);
	list_del_worker(w);
	pthread_mutex_unlock(&mt->lock);
	free(w->buf);
	free(w);
}

int tmfs_session_loop_mt(struct tmfs_session *se)
{
	int err;
	struct tmfs_mt mt;
	struct tmfs_worker *w;

	memset(&mt, 0, sizeof(struct tmfs_mt));
	mt.se = se;
	mt.prevch = tmfs_session_next_chan(se, NULL);
	mt.error = 0;
	mt.numworker = 0;
	mt.numavail = 0;
	mt.main.thread_id = pthread_self();
	mt.main.prev = mt.main.next = &mt.main;
	sem_init(&mt.finish, 0, 0);
	tmfs_mutex_init(&mt.lock);

	pthread_mutex_lock(&mt.lock);
	err = tmfs_loop_start_thread(&mt);
	pthread_mutex_unlock(&mt.lock);
	if (!err) {
		/* sem_wait() is interruptible */
		while (!tmfs_session_exited(se))
			sem_wait(&mt.finish);

		pthread_mutex_lock(&mt.lock);
		for (w = mt.main.next; w != &mt.main; w = w->next)
			pthread_cancel(w->thread_id);
		mt.exit = 1;
		pthread_mutex_unlock(&mt.lock);

		while (mt.main.next != &mt.main)
			tmfs_join_worker(&mt, mt.main.next);

		err = mt.error;
	}

	pthread_mutex_destroy(&mt.lock);
	sem_destroy(&mt.finish);
	tmfs_session_reset(se);
	return err;
}
