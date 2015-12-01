/*
  TMFS: Filesystem in Userspace
  Copyright (C) 2001-2007  Miklos Szeredi <miklos@szeredi.hu>

  This program can be distributed under the terms of the GNU LGPLv2.
  See the file COPYING.LIB
*/

#include "tmfs.h"
#include "tmfs_lowlevel.h"

struct tmfs_chan;
struct tmfs_ll;

struct tmfs_session {
	struct tmfs_session_ops op;

	int (*receive_buf)(struct tmfs_session *se, struct tmfs_buf *buf,
			   struct tmfs_chan **chp);

	void (*process_buf)(void *data, const struct tmfs_buf *buf,
			    struct tmfs_chan *ch);

	void *data;

	volatile int exited;

	struct tmfs_chan *ch;
};

struct tmfs_req {
	struct tmfs_ll *f;
	uint64_t unique;
	int ctr;
	pthread_mutex_t lock;
	struct tmfs_ctx ctx;
	struct tmfs_chan *ch;
	int interrupted;
	unsigned int ioctl_64bit : 1;
	union {
		struct {
			uint64_t unique;
		} i;
		struct {
			tmfs_interrupt_func_t func;
			void *data;
		} ni;
	} u;
	struct tmfs_req *next;
	struct tmfs_req *prev;
};

struct tmfs_notify_req {
	uint64_t unique;
	void (*reply)(struct tmfs_notify_req *, tmfs_req_t, tmfs_ino_t,
		      const void *, const struct tmfs_buf *);
	struct tmfs_notify_req *next;
	struct tmfs_notify_req *prev;
};

struct tmfs_ll {
	int debug;
	int allow_root;
	int atomic_o_trunc;
	int no_remote_posix_lock;
	int no_remote_flock;
	int big_writes;
	int splice_write;
	int splice_move;
	int splice_read;
	int no_splice_write;
	int no_splice_move;
	int no_splice_read;
	struct tmfs_lowlevel_ops op;
	int got_init;
	struct tmcd_data *tmcd_data;
	void *userdata;
	uid_t owner;
	struct tmfs_conn_info conn;
	struct tmfs_req list;
	struct tmfs_req interrupts;
	pthread_mutex_t lock;
	int got_destroy;
	pthread_key_t pipe_key;
	int broken_splice_nonblock;
	uint64_t notify_ctr;
	struct tmfs_notify_req notify_list;
};

struct tmfs_cmd {
	char *buf;
	size_t buflen;
	struct tmfs_chan *ch;
};

struct tmfs *tmfs_new_common(struct tmfs_chan *ch, struct tmfs_args *args,
			     const struct tmfs_operations *op,
			     size_t op_size, void *user_data, int compat);

int tmfs_sync_compat_args(struct tmfs_args *args);

struct tmfs_chan *tmfs_kern_chan_new(int fd);

struct tmfs_session *tmfs_lowlevel_new_common(struct tmfs_args *args,
					const struct tmfs_lowlevel_ops *op,
					size_t op_size, void *userdata);

void tmfs_kern_unmount_compat22(const char *mountpoint);
int tmfs_chan_clearfd(struct tmfs_chan *ch);

void tmfs_kern_unmount(const char *mountpoint, int fd);
int tmfs_kern_mount(const char *mountpoint, struct tmfs_args *args);

int tmfs_send_reply_iov_nofree(tmfs_req_t req, int error, struct iovec *iov,
			       int count);
void tmfs_free_req(tmfs_req_t req);


struct tmfs *tmfs_setup_common(int argc, char *argv[],
			       const struct tmfs_operations *op,
			       size_t op_size,
			       char **mountpoint,
			       int *multithreaded,
			       int *fd,
			       void *user_data,
			       int compat);

void tmcd_lowlevel_init(tmfs_req_t req, tmfs_ino_t nodeide, const void *inarg);

int tmfs_start_thread(pthread_t *thread_id, void *(*func)(void *), void *arg);
