/*
  TMFS: Filesystem in Userspace
  Copyright (C) 2001-2007  Miklos Szeredi <miklos@szeredi.hu>

  This program can be distributed under the terms of the GNU LGPLv2.
  See the file COPYING.LIB
*/

#define _GNU_SOURCE

#include "config.h"
#include "tmfs_i.h"
#include "tmfs_kernel.h"
#include "tmfs_opt.h"
#include "tmfs_misc.h"
#include "tmfs_common_compat.h"
#include "tmfs_lowlevel_compat.h"

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>
#include <errno.h>
#include <assert.h>
#include <sys/file.h>

#ifndef F_LINUX_SPECIFIC_BASE
#define F_LINUX_SPECIFIC_BASE       1024
#endif
#ifndef F_SETPIPE_SZ
#define F_SETPIPE_SZ	(F_LINUX_SPECIFIC_BASE + 7)
#endif


#define PARAM(inarg) (((char *)(inarg)) + sizeof(*(inarg)))
#define OFFSET_MAX 0x7fffffffffffffffLL

#define container_of(ptr, type, member) ({				\
			const typeof( ((type *)0)->member ) *__mptr = (ptr); \
			(type *)( (char *)__mptr - offsetof(type,member) );})

struct tmfs_pollhandle {
	uint64_t kh;
	struct tmfs_chan *ch;
	struct tmfs_ll *f;
};

static size_t pagesize;

static __attribute__((constructor)) void tmfs_ll_init_pagesize(void)
{
	pagesize = getpagesize();
}

static void convert_stat(const struct stat *stbuf, struct tmfs_attr *attr)
{
	attr->ino	= stbuf->st_ino;
	attr->mode	= stbuf->st_mode;
	attr->nlink	= stbuf->st_nlink;
	attr->uid	= stbuf->st_uid;
	attr->gid	= stbuf->st_gid;
	attr->rdev	= stbuf->st_rdev;
	attr->size	= stbuf->st_size;
	attr->blksize	= stbuf->st_blksize;
	attr->blocks	= stbuf->st_blocks;
	attr->atime	= stbuf->st_atime;
	attr->mtime	= stbuf->st_mtime;
	attr->ctime	= stbuf->st_ctime;
	attr->atimensec = ST_ATIM_NSEC(stbuf);
	attr->mtimensec = ST_MTIM_NSEC(stbuf);
	attr->ctimensec = ST_CTIM_NSEC(stbuf);
}

static void convert_attr(const struct tmfs_setattr_in *attr, struct stat *stbuf)
{
	stbuf->st_mode	       = attr->mode;
	stbuf->st_uid	       = attr->uid;
	stbuf->st_gid	       = attr->gid;
	stbuf->st_size	       = attr->size;
	stbuf->st_atime	       = attr->atime;
	stbuf->st_mtime	       = attr->mtime;
	ST_ATIM_NSEC_SET(stbuf, attr->atimensec);
	ST_MTIM_NSEC_SET(stbuf, attr->mtimensec);
}

static	size_t iov_length(const struct iovec *iov, size_t count)
{
	size_t seg;
	size_t ret = 0;

	for (seg = 0; seg < count; seg++)
		ret += iov[seg].iov_len;
	return ret;
}

static void list_init_req(struct tmfs_req *req)
{
	req->next = req;
	req->prev = req;
}

static void list_del_req(struct tmfs_req *req)
{
	struct tmfs_req *prev = req->prev;
	struct tmfs_req *next = req->next;
	prev->next = next;
	next->prev = prev;
}

static void list_add_req(struct tmfs_req *req, struct tmfs_req *next)
{
	struct tmfs_req *prev = next->prev;
	req->next = next;
	req->prev = prev;
	prev->next = req;
	next->prev = req;
}

static void destroy_req(tmfs_req_t req)
{
	pthread_mutex_destroy(&req->lock);
	free(req);
}

void tmfs_free_req(tmfs_req_t req)
{
	int ctr;
	struct tmfs_ll *f = req->f;

	pthread_mutex_lock(&f->lock);
	req->u.ni.func = NULL;
	req->u.ni.data = NULL;
	list_del_req(req);
	ctr = --req->ctr;
	pthread_mutex_unlock(&f->lock);
	if (!ctr)
		destroy_req(req);
}

static struct tmfs_req *tmfs_ll_alloc_req(struct tmfs_ll *f)
{
	struct tmfs_req *req;

	req = (struct tmfs_req *) calloc(1, sizeof(struct tmfs_req));
	if (req == NULL) {
		fprintf(stderr, "tmfs: failed to allocate request\n");
	} else {
		req->f = f;
		req->ctr = 1;
		list_init_req(req);
		tmfs_mutex_init(&req->lock);
	}

	return req;
}


static int tmfs_send_msg(struct tmfs_ll *f, struct tmfs_chan *ch,
			 struct iovec *iov, int count)
{
	struct tmfs_out_header *out = iov[0].iov_base;

	out->len = iov_length(iov, count);
	if (f->debug) {
		if (out->unique == 0) {
			fprintf(stderr, "NOTIFY: code=%d length=%u\n",
				out->error, out->len);
		} else if (out->error) {
			fprintf(stderr,
				"   unique: %llu, error: %i (%s), outsize: %i\n",
				(unsigned long long) out->unique, out->error,
				strerror(-out->error), out->len);
		} else {
			fprintf(stderr,
				"   unique: %llu, success, outsize: %i\n",
				(unsigned long long) out->unique, out->len);
		}
	}

	return tmfs_chan_send(ch, iov, count);
}

int tmfs_send_reply_iov_nofree(tmfs_req_t req, int error, struct iovec *iov,
			       int count)
{
	struct tmfs_out_header out;

	if (error <= -1000 || error > 0) {
		fprintf(stderr, "tmfs: bad error value: %i\n",	error);
		error = -ERANGE;
	}

	out.unique = req->unique;
	out.error = error;

	iov[0].iov_base = &out;
	iov[0].iov_len = sizeof(struct tmfs_out_header);

	return tmfs_send_msg(req->f, req->ch, iov, count);
}

static int send_reply_iov(tmfs_req_t req, int error, struct iovec *iov,
			  int count)
{
	int res;

	res = tmfs_send_reply_iov_nofree(req, error, iov, count);
	tmfs_free_req(req);
	return res;
}

static int send_reply(tmfs_req_t req, int error, const void *arg,
		      size_t argsize)
{
	struct iovec iov[2];
	int count = 1;
	if (argsize) {
		iov[1].iov_base = (void *) arg;
		iov[1].iov_len = argsize;
		count++;
	}
	return send_reply_iov(req, error, iov, count);
}

int tmfs_reply_iov(tmfs_req_t req, const struct iovec *iov, int count)
{
	int res;
	struct iovec *padded_iov;

	padded_iov = malloc((count + 1) * sizeof(struct iovec));
	if (padded_iov == NULL)
		return tmfs_reply_err(req, ENOMEM);

	memcpy(padded_iov + 1, iov, count * sizeof(struct iovec));
	count++;

	res = send_reply_iov(req, 0, padded_iov, count);
	free(padded_iov);

	return res;
}

size_t tmfs_dirent_size(size_t namelen)
{
	return TMFS_DIRENT_ALIGN(TMFS_NAME_OFFSET + namelen);
}

char *tmfs_add_dirent(char *buf, const char *name, const struct stat *stbuf,
		      off_t off)
{
	unsigned namelen = strlen(name);
	unsigned entlen = TMFS_NAME_OFFSET + namelen;
	unsigned entsize = tmfs_dirent_size(namelen);
	unsigned padlen = entsize - entlen;
	struct tmfs_dirent *dirent = (struct tmfs_dirent *) buf;

	dirent->ino = stbuf->st_ino;
	dirent->off = off;
	dirent->namelen = namelen;
	dirent->type = (stbuf->st_mode & 0170000) >> 12;
	strncpy(dirent->name, name, namelen);
	if (padlen)
		memset(buf + entlen, 0, padlen);

	return buf + entsize;
}

size_t tmfs_add_direntry(tmfs_req_t req, char *buf, size_t bufsize,
			 const char *name, const struct stat *stbuf, off_t off)
{
	size_t entsize;

	(void) req;
	entsize = tmfs_dirent_size(strlen(name));
	if (entsize <= bufsize && buf)
		tmfs_add_dirent(buf, name, stbuf, off);
	return entsize;
}

static void convert_statfs(const struct statvfs *stbuf,
			   struct tmfs_kstatfs *kstatfs)
{
	kstatfs->bsize	 = stbuf->f_bsize;
	kstatfs->frsize	 = stbuf->f_frsize;
	kstatfs->blocks	 = stbuf->f_blocks;
	kstatfs->bfree	 = stbuf->f_bfree;
	kstatfs->bavail	 = stbuf->f_bavail;
	kstatfs->files	 = stbuf->f_files;
	kstatfs->ffree	 = stbuf->f_ffree;
	kstatfs->namelen = stbuf->f_namemax;
}

static int send_reply_ok(tmfs_req_t req, const void *arg, size_t argsize)
{
	return send_reply(req, 0, arg, argsize);
}

int tmfs_reply_err(tmfs_req_t req, int err)
{
	return send_reply(req, -err, NULL, 0);
}

void tmfs_reply_none(tmfs_req_t req)
{
	if (req->ch)
		tmfs_chan_send(req->ch, NULL, 0);
	tmfs_free_req(req);
}

static unsigned long calc_timeout_sec(double t)
{
	if (t > (double) ULONG_MAX)
		return ULONG_MAX;
	else if (t < 0.0)
		return 0;
	else
		return (unsigned long) t;
}

static unsigned int calc_timeout_nsec(double t)
{
	double f = t - (double) calc_timeout_sec(t);
	if (f < 0.0)
		return 0;
	else if (f >= 0.999999999)
		return 999999999;
	else
		return (unsigned int) (f * 1.0e9);
}

static void fill_entry(struct tmfs_entry_out *arg,
		       const struct tmfs_entry_param *e)
{
	arg->nodeid = e->ino;
	arg->generation = e->generation;
	arg->entry_valid = calc_timeout_sec(e->entry_timeout);
	arg->entry_valid_nsec = calc_timeout_nsec(e->entry_timeout);
	arg->attr_valid = calc_timeout_sec(e->attr_timeout);
	arg->attr_valid_nsec = calc_timeout_nsec(e->attr_timeout);
	convert_stat(&e->attr, &arg->attr);
}

static void fill_open(struct tmfs_open_out *arg,
		      const struct tmfs_file_info *f)
{
	arg->fh = f->fh;
	if (f->direct_io)
		arg->open_flags |= FOPEN_DIRECT_IO;
	if (f->keep_cache)
		arg->open_flags |= FOPEN_KEEP_CACHE;
	if (f->nonseekable)
		arg->open_flags |= FOPEN_NONSEEKABLE;
}

int tmfs_reply_entry(tmfs_req_t req, const struct tmfs_entry_param *e)
{
	struct tmfs_entry_out arg;
	size_t size = req->f->conn.proto_minor < 9 ?
		TMFS_COMPAT_ENTRY_OUT_SIZE : sizeof(arg);

	/* before ABI 7.4 e->ino == 0 was invalid, only ENOENT meant
	   negative entry */
	if (!e->ino && req->f->conn.proto_minor < 4)
		return tmfs_reply_err(req, ENOENT);

	memset(&arg, 0, sizeof(arg));
	fill_entry(&arg, e);
	return send_reply_ok(req, &arg, size);
}

int tmfs_reply_create(tmfs_req_t req, const struct tmfs_entry_param *e,
		      const struct tmfs_file_info *f)
{
	char buf[sizeof(struct tmfs_entry_out) + sizeof(struct tmfs_open_out)];
	size_t entrysize = req->f->conn.proto_minor < 9 ?
		TMFS_COMPAT_ENTRY_OUT_SIZE : sizeof(struct tmfs_entry_out);
	struct tmfs_entry_out *earg = (struct tmfs_entry_out *) buf;
	struct tmfs_open_out *oarg = (struct tmfs_open_out *) (buf + entrysize);

	memset(buf, 0, sizeof(buf));
	fill_entry(earg, e);
	fill_open(oarg, f);
	return send_reply_ok(req, buf,
			     entrysize + sizeof(struct tmfs_open_out));
}

int tmfs_reply_attr(tmfs_req_t req, const struct stat *attr,
		    double attr_timeout)
{
	struct tmfs_attr_out arg;
	size_t size = req->f->conn.proto_minor < 9 ?
		TMFS_COMPAT_ATTR_OUT_SIZE : sizeof(arg);

	memset(&arg, 0, sizeof(arg));
	arg.attr_valid = calc_timeout_sec(attr_timeout);
	arg.attr_valid_nsec = calc_timeout_nsec(attr_timeout);
	convert_stat(attr, &arg.attr);

	return send_reply_ok(req, &arg, size);
}

int tmfs_reply_readlink(tmfs_req_t req, const char *linkname)
{
	return send_reply_ok(req, linkname, strlen(linkname));
}

int tmfs_reply_open(tmfs_req_t req, const struct tmfs_file_info *f)
{
	struct tmfs_open_out arg;

	memset(&arg, 0, sizeof(arg));
	fill_open(&arg, f);
	return send_reply_ok(req, &arg, sizeof(arg));
}

int tmfs_reply_write(tmfs_req_t req, size_t count)
{
	struct tmfs_write_out arg;

	memset(&arg, 0, sizeof(arg));
	arg.size = count;

	return send_reply_ok(req, &arg, sizeof(arg));
}

int tmfs_reply_buf(tmfs_req_t req, const char *buf, size_t size)
{
	return send_reply_ok(req, buf, size);
}

static int tmfs_send_data_iov_fallback(struct tmfs_ll *f, struct tmfs_chan *ch,
				       struct iovec *iov, int iov_count,
				       struct tmfs_bufvec *buf,
				       size_t len)
{
	struct tmfs_bufvec mem_buf = TMFS_BUFVEC_INIT(len);
	void *mbuf;
	int res;

	/* Optimize common case */
	if (buf->count == 1 && buf->idx == 0 && buf->off == 0 &&
	    !(buf->buf[0].flags & TMFS_BUF_IS_FD)) {
		/* FIXME: also avoid memory copy if there are multiple buffers
		   but none of them contain an fd */

		iov[iov_count].iov_base = buf->buf[0].mem;
		iov[iov_count].iov_len = len;
		iov_count++;
		return tmfs_send_msg(f, ch, iov, iov_count);
	}

	res = posix_memalign(&mbuf, pagesize, len);
	if (res != 0)
		return res;

	mem_buf.buf[0].mem = mbuf;
	res = tmfs_buf_copy(&mem_buf, buf, 0);
	if (res < 0) {
		free(mbuf);
		return -res;
	}
	len = res;

	iov[iov_count].iov_base = mbuf;
	iov[iov_count].iov_len = len;
	iov_count++;
	res = tmfs_send_msg(f, ch, iov, iov_count);
	free(mbuf);

	return res;
}

struct tmfs_ll_pipe {
	size_t size;
	int can_grow;
	int pipe[2];
};

static void tmfs_ll_pipe_free(struct tmfs_ll_pipe *llp)
{
	close(llp->pipe[0]);
	close(llp->pipe[1]);
	free(llp);
}

#ifdef HAVE_SPLICE
static struct tmfs_ll_pipe *tmfs_ll_get_pipe(struct tmfs_ll *f)
{
	struct tmfs_ll_pipe *llp = pthread_getspecific(f->pipe_key);
	if (llp == NULL) {
		int res;

		llp = malloc(sizeof(struct tmfs_ll_pipe));
		if (llp == NULL)
			return NULL;

		res = pipe(llp->pipe);
		if (res == -1) {
			free(llp);
			return NULL;
		}

		if (fcntl(llp->pipe[0], F_SETFL, O_NONBLOCK) == -1 ||
		    fcntl(llp->pipe[1], F_SETFL, O_NONBLOCK) == -1) {
			close(llp->pipe[0]);
			close(llp->pipe[1]);
			free(llp);
			return NULL;
		}

		/*
		 *the default size is 16 pages on linux
		 */
		llp->size = pagesize * 16;
		llp->can_grow = 1;

		pthread_setspecific(f->pipe_key, llp);
	}

	return llp;
}
#endif

static void tmfs_ll_clear_pipe(struct tmfs_ll *f)
{
	struct tmfs_ll_pipe *llp = pthread_getspecific(f->pipe_key);
	if (llp) {
		pthread_setspecific(f->pipe_key, NULL);
		tmfs_ll_pipe_free(llp);
	}
}

#if defined(HAVE_SPLICE) && defined(HAVE_VMSPLICE)
static int read_back(int fd, char *buf, size_t len)
{
	int res;

	res = read(fd, buf, len);
	if (res == -1) {
		fprintf(stderr, "tmfs: internal error: failed to read back from pipe: %s\n", strerror(errno));
		return -EIO;
	}
	if (res != len) {
		fprintf(stderr, "tmfs: internal error: short read back from pipe: %i from %zi\n", res, len);
		return -EIO;
	}
	return 0;
}

static int tmfs_send_data_iov(struct tmfs_ll *f, struct tmfs_chan *ch,
			       struct iovec *iov, int iov_count,
			       struct tmfs_bufvec *buf, unsigned int flags)
{
	int res;
	size_t len = tmfs_buf_size(buf);
	struct tmfs_out_header *out = iov[0].iov_base;
	struct tmfs_ll_pipe *llp;
	int splice_flags;
	size_t pipesize;
	size_t total_fd_size;
	size_t idx;
	size_t headerlen;
	struct tmfs_bufvec pipe_buf = TMFS_BUFVEC_INIT(len);

	if (f->broken_splice_nonblock)
		goto fallback;

	if (flags & TMFS_BUF_NO_SPLICE)
		goto fallback;

	total_fd_size = 0;
	for (idx = buf->idx; idx < buf->count; idx++) {
		if (buf->buf[idx].flags & TMFS_BUF_IS_FD) {
			total_fd_size = buf->buf[idx].size;
			if (idx == buf->idx)
				total_fd_size -= buf->off;
		}
	}
	if (total_fd_size < 2 * pagesize)
		goto fallback;

	if (f->conn.proto_minor < 14 ||
	    !(f->conn.want & TMFS_CAP_SPLICE_WRITE))
		goto fallback;

	llp = tmfs_ll_get_pipe(f);
	if (llp == NULL)
		goto fallback;


	headerlen = iov_length(iov, iov_count);

	out->len = headerlen + len;

	/*
	 * Heuristic for the required pipe size, does not work if the
	 * source contains less than page size fragments
	 */
	pipesize = pagesize * (iov_count + buf->count + 1) + out->len;

	if (llp->size < pipesize) {
		if (llp->can_grow) {
			res = fcntl(llp->pipe[0], F_SETPIPE_SZ, pipesize);
			if (res == -1) {
				llp->can_grow = 0;
				goto fallback;
			}
			llp->size = res;
		}
		if (llp->size < pipesize)
			goto fallback;
	}


	res = vmsplice(llp->pipe[1], iov, iov_count, SPLICE_F_NONBLOCK);
	if (res == -1)
		goto fallback;

	if (res != headerlen) {
		res = -EIO;
		fprintf(stderr, "tmfs: short vmsplice to pipe: %u/%zu\n", res,
			headerlen);
		goto clear_pipe;
	}

	pipe_buf.buf[0].flags = TMFS_BUF_IS_FD;
	pipe_buf.buf[0].fd = llp->pipe[1];

	res = tmfs_buf_copy(&pipe_buf, buf,
			    TMFS_BUF_FORCE_SPLICE | TMFS_BUF_SPLICE_NONBLOCK);
	if (res < 0) {
		if (res == -EAGAIN || res == -EINVAL) {
			/*
			 * Should only get EAGAIN on kernels with
			 * broken SPLICE_F_NONBLOCK support (<=
			 * 2.6.35) where this error or a short read is
			 * returned even if the pipe itself is not
			 * full
			 *
			 * EINVAL might mean that splice can't handle
			 * this combination of input and output.
			 */
			if (res == -EAGAIN)
				f->broken_splice_nonblock = 1;

			pthread_setspecific(f->pipe_key, NULL);
			tmfs_ll_pipe_free(llp);
			goto fallback;
		}
		res = -res;
		goto clear_pipe;
	}

	if (res != 0 && res < len) {
		struct tmfs_bufvec mem_buf = TMFS_BUFVEC_INIT(len);
		void *mbuf;
		size_t now_len = res;
		/*
		 * For regular files a short count is either
		 *  1) due to EOF, or
		 *  2) because of broken SPLICE_F_NONBLOCK (see above)
		 *
		 * For other inputs it's possible that we overflowed
		 * the pipe because of small buffer fragments.
		 */

		res = posix_memalign(&mbuf, pagesize, len);
		if (res != 0)
			goto clear_pipe;

		mem_buf.buf[0].mem = mbuf;
		mem_buf.off = now_len;
		res = tmfs_buf_copy(&mem_buf, buf, 0);
		if (res > 0) {
			char *tmpbuf;
			size_t extra_len = res;
			/*
			 * Trickiest case: got more data.  Need to get
			 * back the data from the pipe and then fall
			 * back to regular write.
			 */
			tmpbuf = malloc(headerlen);
			if (tmpbuf == NULL) {
				free(mbuf);
				res = ENOMEM;
				goto clear_pipe;
			}
			res = read_back(llp->pipe[0], tmpbuf, headerlen);
			if (res != 0) {
				free(mbuf);
				goto clear_pipe;
			}
			free(tmpbuf);
			res = read_back(llp->pipe[0], mbuf, now_len);
			if (res != 0) {
				free(mbuf);
				goto clear_pipe;
			}
			len = now_len + extra_len;
			iov[iov_count].iov_base = mbuf;
			iov[iov_count].iov_len = len;
			iov_count++;
			res = tmfs_send_msg(f, ch, iov, iov_count);
			free(mbuf);
			return res;
		}
		free(mbuf);
		res = now_len;
	}
	len = res;
	out->len = headerlen + len;

	if (f->debug) {
		fprintf(stderr,
			"   unique: %llu, success, outsize: %i (splice)\n",
			(unsigned long long) out->unique, out->len);
	}

	splice_flags = 0;
	if ((flags & TMFS_BUF_SPLICE_MOVE) &&
	    (f->conn.want & TMFS_CAP_SPLICE_MOVE))
		splice_flags |= SPLICE_F_MOVE;

	res = splice(llp->pipe[0], NULL,
		     tmfs_chan_fd(ch), NULL, out->len, splice_flags);
	if (res == -1) {
		res = -errno;
		perror("tmfs: splice from pipe");
		goto clear_pipe;
	}
	if (res != out->len) {
		res = -EIO;
		fprintf(stderr, "tmfs: short splice from pipe: %u/%u\n",
			res, out->len);
		goto clear_pipe;
	}
	return 0;

clear_pipe:
	tmfs_ll_clear_pipe(f);
	return res;

fallback:
	return tmfs_send_data_iov_fallback(f, ch, iov, iov_count, buf, len);
}
#else
static int tmfs_send_data_iov(struct tmfs_ll *f, struct tmfs_chan *ch,
			       struct iovec *iov, int iov_count,
			       struct tmfs_bufvec *buf, unsigned int flags)
{
	size_t len = tmfs_buf_size(buf);
	(void) flags;

	return tmfs_send_data_iov_fallback(f, ch, iov, iov_count, buf, len);
}
#endif

int tmfs_reply_data(tmfs_req_t req, struct tmfs_bufvec *bufv,
		    enum tmfs_buf_copy_flags flags)
{
	struct iovec iov[2];
	struct tmfs_out_header out;
	int res;

	iov[0].iov_base = &out;
	iov[0].iov_len = sizeof(struct tmfs_out_header);

	out.unique = req->unique;
	out.error = 0;

	res = tmfs_send_data_iov(req->f, req->ch, iov, 1, bufv, flags);
	if (res <= 0) {
		tmfs_free_req(req);
		return res;
	} else {
		return tmfs_reply_err(req, res);
	}
}

int tmfs_reply_statfs(tmfs_req_t req, const struct statvfs *stbuf)
{
	struct tmfs_statfs_out arg;
	size_t size = req->f->conn.proto_minor < 4 ?
		TMFS_COMPAT_STATFS_SIZE : sizeof(arg);

	memset(&arg, 0, sizeof(arg));
	convert_statfs(stbuf, &arg.st);

	return send_reply_ok(req, &arg, size);
}

int tmfs_reply_xattr(tmfs_req_t req, size_t count)
{
	struct tmfs_getxattr_out arg;

	memset(&arg, 0, sizeof(arg));
	arg.size = count;

	return send_reply_ok(req, &arg, sizeof(arg));
}

int tmfs_reply_lock(tmfs_req_t req, const struct flock *lock)
{
	struct tmfs_lk_out arg;

	memset(&arg, 0, sizeof(arg));
	arg.lk.type = lock->l_type;
	if (lock->l_type != F_UNLCK) {
		arg.lk.start = lock->l_start;
		if (lock->l_len == 0)
			arg.lk.end = OFFSET_MAX;
		else
			arg.lk.end = lock->l_start + lock->l_len - 1;
	}
	arg.lk.pid = lock->l_pid;
	return send_reply_ok(req, &arg, sizeof(arg));
}

int tmfs_reply_bmap(tmfs_req_t req, uint64_t idx)
{
	struct tmfs_bmap_out arg;

	memset(&arg, 0, sizeof(arg));
	arg.block = idx;

	return send_reply_ok(req, &arg, sizeof(arg));
}

static struct tmfs_ioctl_iovec *tmfs_ioctl_iovec_copy(const struct iovec *iov,
						      size_t count)
{
	struct tmfs_ioctl_iovec *fiov;
	size_t i;

	fiov = malloc(sizeof(fiov[0]) * count);
	if (!fiov)
		return NULL;

	for (i = 0; i < count; i++) {
		fiov[i].base = (uintptr_t) iov[i].iov_base;
		fiov[i].len = iov[i].iov_len;
	}

	return fiov;
}

int tmfs_reply_ioctl_retry(tmfs_req_t req,
			   const struct iovec *in_iov, size_t in_count,
			   const struct iovec *out_iov, size_t out_count)
{
	struct tmfs_ioctl_out arg;
	struct tmfs_ioctl_iovec *in_fiov = NULL;
	struct tmfs_ioctl_iovec *out_fiov = NULL;
	struct iovec iov[4];
	size_t count = 1;
	int res;

	memset(&arg, 0, sizeof(arg));
	arg.flags |= TMFS_IOCTL_RETRY;
	arg.in_iovs = in_count;
	arg.out_iovs = out_count;
	iov[count].iov_base = &arg;
	iov[count].iov_len = sizeof(arg);
	count++;

	if (req->f->conn.proto_minor < 16) {
		if (in_count) {
			iov[count].iov_base = (void *)in_iov;
			iov[count].iov_len = sizeof(in_iov[0]) * in_count;
			count++;
		}

		if (out_count) {
			iov[count].iov_base = (void *)out_iov;
			iov[count].iov_len = sizeof(out_iov[0]) * out_count;
			count++;
		}
	} else {
		/* Can't handle non-compat 64bit ioctls on 32bit */
		if (sizeof(void *) == 4 && req->ioctl_64bit) {
			res = tmfs_reply_err(req, EINVAL);
			goto out;
		}

		if (in_count) {
			in_fiov = tmfs_ioctl_iovec_copy(in_iov, in_count);
			if (!in_fiov)
				goto enomem;

			iov[count].iov_base = (void *)in_fiov;
			iov[count].iov_len = sizeof(in_fiov[0]) * in_count;
			count++;
		}
		if (out_count) {
			out_fiov = tmfs_ioctl_iovec_copy(out_iov, out_count);
			if (!out_fiov)
				goto enomem;

			iov[count].iov_base = (void *)out_fiov;
			iov[count].iov_len = sizeof(out_fiov[0]) * out_count;
			count++;
		}
	}

	res = send_reply_iov(req, 0, iov, count);
out:
	free(in_fiov);
	free(out_fiov);

	return res;

enomem:
	res = tmfs_reply_err(req, ENOMEM);
	goto out;
}

int tmfs_reply_ioctl(tmfs_req_t req, int result, const void *buf, size_t size)
{
	struct tmfs_ioctl_out arg;
	struct iovec iov[3];
	size_t count = 1;

	memset(&arg, 0, sizeof(arg));
	arg.result = result;
	iov[count].iov_base = &arg;
	iov[count].iov_len = sizeof(arg);
	count++;

	if (size) {
		iov[count].iov_base = (char *) buf;
		iov[count].iov_len = size;
		count++;
	}

	return send_reply_iov(req, 0, iov, count);
}

int tmfs_reply_ioctl_iov(tmfs_req_t req, int result, const struct iovec *iov,
			 int count)
{
	struct iovec *padded_iov;
	struct tmfs_ioctl_out arg;
	int res;

	padded_iov = malloc((count + 2) * sizeof(struct iovec));
	if (padded_iov == NULL)
		return tmfs_reply_err(req, ENOMEM);

	memset(&arg, 0, sizeof(arg));
	arg.result = result;
	padded_iov[1].iov_base = &arg;
	padded_iov[1].iov_len = sizeof(arg);

	memcpy(&padded_iov[2], iov, count * sizeof(struct iovec));

	res = send_reply_iov(req, 0, padded_iov, count + 2);
	free(padded_iov);

	return res;
}

int tmfs_reply_poll(tmfs_req_t req, unsigned revents)
{
	struct tmfs_poll_out arg;

	memset(&arg, 0, sizeof(arg));
	arg.revents = revents;

	return send_reply_ok(req, &arg, sizeof(arg));
}

static void do_lookup(tmfs_req_t req, tmfs_ino_t nodeid, const void *inarg)
{
	char *name = (char *) inarg;

	if (req->f->op.lookup)
		req->f->op.lookup(req, nodeid, name);
	else
		tmfs_reply_err(req, ENOSYS);
}

static void do_forget(tmfs_req_t req, tmfs_ino_t nodeid, const void *inarg)
{
	struct tmfs_forget_in *arg = (struct tmfs_forget_in *) inarg;

	if (req->f->op.forget)
		req->f->op.forget(req, nodeid, arg->nlookup);
	else
		tmfs_reply_none(req);
}

static void do_batch_forget(tmfs_req_t req, tmfs_ino_t nodeid,
			    const void *inarg)
{
	struct tmfs_batch_forget_in *arg = (void *) inarg;
	struct tmfs_forget_one *param = (void *) PARAM(arg);
	unsigned int i;

	(void) nodeid;

	if (req->f->op.forget_multi) {
		req->f->op.forget_multi(req, arg->count,
				     (struct tmfs_forget_data *) param);
	} else if (req->f->op.forget) {
		for (i = 0; i < arg->count; i++) {
			struct tmfs_forget_one *forget = &param[i];
			struct tmfs_req *dummy_req;

			dummy_req = tmfs_ll_alloc_req(req->f);
			if (dummy_req == NULL)
				break;

			dummy_req->unique = req->unique;
			dummy_req->ctx = req->ctx;
			dummy_req->ch = NULL;

			req->f->op.forget(dummy_req, forget->nodeid,
					  forget->nlookup);
		}
		tmfs_reply_none(req);
	} else {
		tmfs_reply_none(req);
	}
}

static void do_getattr(tmfs_req_t req, tmfs_ino_t nodeid, const void *inarg)
{
	struct tmfs_file_info *fip = NULL;
	struct tmfs_file_info fi;

	if (req->f->conn.proto_minor >= 9) {
		struct tmfs_getattr_in *arg = (struct tmfs_getattr_in *) inarg;

		if (arg->getattr_flags & TMFS_GETATTR_FH) {
			memset(&fi, 0, sizeof(fi));
			fi.fh = arg->fh;
			fi.fh_old = fi.fh;
			fip = &fi;
		}
	}

	if (req->f->op.getattr)
		req->f->op.getattr(req, nodeid, fip);
	else
		tmfs_reply_err(req, ENOSYS);
}

static void do_setattr(tmfs_req_t req, tmfs_ino_t nodeid, const void *inarg)
{
	struct tmfs_setattr_in *arg = (struct tmfs_setattr_in *) inarg;

	if (req->f->op.setattr) {
		struct tmfs_file_info *fi = NULL;
		struct tmfs_file_info fi_store;
		struct stat stbuf;
		memset(&stbuf, 0, sizeof(stbuf));
		convert_attr(arg, &stbuf);
		if (arg->valid & FATTR_FH) {
			arg->valid &= ~FATTR_FH;
			memset(&fi_store, 0, sizeof(fi_store));
			fi = &fi_store;
			fi->fh = arg->fh;
			fi->fh_old = fi->fh;
		}
		arg->valid &=
			TMFS_SET_ATTR_MODE	|
			TMFS_SET_ATTR_UID	|
			TMFS_SET_ATTR_GID	|
			TMFS_SET_ATTR_SIZE	|
			TMFS_SET_ATTR_ATIME	|
			TMFS_SET_ATTR_MTIME	|
			TMFS_SET_ATTR_ATIME_NOW	|
			TMFS_SET_ATTR_MTIME_NOW;

		req->f->op.setattr(req, nodeid, &stbuf, arg->valid, fi);
	} else
		tmfs_reply_err(req, ENOSYS);
}

static void do_access(tmfs_req_t req, tmfs_ino_t nodeid, const void *inarg)
{
	struct tmfs_access_in *arg = (struct tmfs_access_in *) inarg;

	if (req->f->op.access)
		req->f->op.access(req, nodeid, arg->mask);
	else
		tmfs_reply_err(req, ENOSYS);
}

static void do_readlink(tmfs_req_t req, tmfs_ino_t nodeid, const void *inarg)
{
	(void) inarg;

	if (req->f->op.readlink)
		req->f->op.readlink(req, nodeid);
	else
		tmfs_reply_err(req, ENOSYS);
}

static void do_mknod(tmfs_req_t req, tmfs_ino_t nodeid, const void *inarg)
{
	struct tmfs_mknod_in *arg = (struct tmfs_mknod_in *) inarg;
	char *name = PARAM(arg);

	if (req->f->conn.proto_minor >= 12)
		req->ctx.umask = arg->umask;
	else
		name = (char *) inarg + TMFS_COMPAT_MKNOD_IN_SIZE;

	if (req->f->op.mknod)
		req->f->op.mknod(req, nodeid, name, arg->mode, arg->rdev);
	else
		tmfs_reply_err(req, ENOSYS);
}

static void do_mkdir(tmfs_req_t req, tmfs_ino_t nodeid, const void *inarg)
{
	struct tmfs_mkdir_in *arg = (struct tmfs_mkdir_in *) inarg;

	if (req->f->conn.proto_minor >= 12)
		req->ctx.umask = arg->umask;

	if (req->f->op.mkdir)
		req->f->op.mkdir(req, nodeid, PARAM(arg), arg->mode);
	else
		tmfs_reply_err(req, ENOSYS);
}

static void do_unlink(tmfs_req_t req, tmfs_ino_t nodeid, const void *inarg)
{
	char *name = (char *) inarg;

	if (req->f->op.unlink)
		req->f->op.unlink(req, nodeid, name);
	else
		tmfs_reply_err(req, ENOSYS);
}

static void do_rmdir(tmfs_req_t req, tmfs_ino_t nodeid, const void *inarg)
{
	char *name = (char *) inarg;

	if (req->f->op.rmdir)
		req->f->op.rmdir(req, nodeid, name);
	else
		tmfs_reply_err(req, ENOSYS);
}

static void do_symlink(tmfs_req_t req, tmfs_ino_t nodeid, const void *inarg)
{
	char *name = (char *) inarg;
	char *linkname = ((char *) inarg) + strlen((char *) inarg) + 1;

	if (req->f->op.symlink)
		req->f->op.symlink(req, linkname, nodeid, name);
	else
		tmfs_reply_err(req, ENOSYS);
}

static void do_rename(tmfs_req_t req, tmfs_ino_t nodeid, const void *inarg)
{
	struct tmfs_rename_in *arg = (struct tmfs_rename_in *) inarg;
	char *oldname = PARAM(arg);
	char *newname = oldname + strlen(oldname) + 1;

	if (req->f->op.rename)
		req->f->op.rename(req, nodeid, oldname, arg->newdir, newname);
	else
		tmfs_reply_err(req, ENOSYS);
}

static void do_link(tmfs_req_t req, tmfs_ino_t nodeid, const void *inarg)
{
	struct tmfs_link_in *arg = (struct tmfs_link_in *) inarg;

	if (req->f->op.link)
		req->f->op.link(req, arg->oldnodeid, nodeid, PARAM(arg));
	else
		tmfs_reply_err(req, ENOSYS);
}

static void do_create(tmfs_req_t req, tmfs_ino_t nodeid, const void *inarg)
{
	struct tmfs_create_in *arg = (struct tmfs_create_in *) inarg;

	if (req->f->op.create) {
		struct tmfs_file_info fi;
		char *name = PARAM(arg);

		memset(&fi, 0, sizeof(fi));
		fi.flags = arg->flags;

		if (req->f->conn.proto_minor >= 12)
			req->ctx.umask = arg->umask;
		else
			name = (char *) inarg + sizeof(struct tmfs_open_in);

		req->f->op.create(req, nodeid, name, arg->mode, &fi);
	} else
		tmfs_reply_err(req, ENOSYS);
}

static void do_open(tmfs_req_t req, tmfs_ino_t nodeid, const void *inarg)
{
	struct tmfs_open_in *arg = (struct tmfs_open_in *) inarg;
	struct tmfs_file_info fi;

	memset(&fi, 0, sizeof(fi));
	fi.flags = arg->flags;

	if (req->f->op.open)
		req->f->op.open(req, nodeid, &fi);
	else
		tmfs_reply_open(req, &fi);
}

static void do_read(tmfs_req_t req, tmfs_ino_t nodeid, const void *inarg)
{
	struct tmfs_read_in *arg = (struct tmfs_read_in *) inarg;

	if (req->f->op.read) {
		struct tmfs_file_info fi;

		memset(&fi, 0, sizeof(fi));
		fi.fh = arg->fh;
		fi.fh_old = fi.fh;
		if (req->f->conn.proto_minor >= 9) {
			fi.lock_owner = arg->lock_owner;
			fi.flags = arg->flags;
		}
		req->f->op.read(req, nodeid, arg->size, arg->offset, &fi);
	} else
		tmfs_reply_err(req, ENOSYS);
}

static void do_write(tmfs_req_t req, tmfs_ino_t nodeid, const void *inarg)
{
	struct tmfs_write_in *arg = (struct tmfs_write_in *) inarg;
	struct tmfs_file_info fi;
	char *param;

	memset(&fi, 0, sizeof(fi));
	fi.fh = arg->fh;
	fi.fh_old = fi.fh;
	fi.writepage = arg->write_flags & 1;

	if (req->f->conn.proto_minor < 9) {
		param = ((char *) arg) + TMFS_COMPAT_WRITE_IN_SIZE;
	} else {
		fi.lock_owner = arg->lock_owner;
		fi.flags = arg->flags;
		param = PARAM(arg);
	}

	if (req->f->op.write)
		req->f->op.write(req, nodeid, param, arg->size,
				 arg->offset, &fi);
	else
		tmfs_reply_err(req, ENOSYS);
}

static void do_write_buf(tmfs_req_t req, tmfs_ino_t nodeid, const void *inarg,
			 const struct tmfs_buf *ibuf)
{
	struct tmfs_ll *f = req->f;
	struct tmfs_bufvec bufv = {
		.buf[0] = *ibuf,
		.count = 1,
	};
	struct tmfs_write_in *arg = (struct tmfs_write_in *) inarg;
	struct tmfs_file_info fi;

	memset(&fi, 0, sizeof(fi));
	fi.fh = arg->fh;
	fi.fh_old = fi.fh;
	fi.writepage = arg->write_flags & 1;

	if (req->f->conn.proto_minor < 9) {
		bufv.buf[0].mem = ((char *) arg) + TMFS_COMPAT_WRITE_IN_SIZE;
		bufv.buf[0].size -= sizeof(struct tmfs_in_header) +
			TMFS_COMPAT_WRITE_IN_SIZE;
		assert(!(bufv.buf[0].flags & TMFS_BUF_IS_FD));
	} else {
		fi.lock_owner = arg->lock_owner;
		fi.flags = arg->flags;
		if (!(bufv.buf[0].flags & TMFS_BUF_IS_FD))
			bufv.buf[0].mem = PARAM(arg);

		bufv.buf[0].size -= sizeof(struct tmfs_in_header) +
			sizeof(struct tmfs_write_in);
	}
	if (bufv.buf[0].size < arg->size) {
		fprintf(stderr, "tmfs: do_write_buf: buffer size too small\n");
		tmfs_reply_err(req, EIO);
		goto out;
	}
	bufv.buf[0].size = arg->size;

	req->f->op.write_buf(req, nodeid, &bufv, arg->offset, &fi);

out:
	/* Need to reset the pipe if ->write_buf() didn't consume all data */
	if ((ibuf->flags & TMFS_BUF_IS_FD) && bufv.idx < bufv.count)
		tmfs_ll_clear_pipe(f);
}

static void do_flush(tmfs_req_t req, tmfs_ino_t nodeid, const void *inarg)
{
	struct tmfs_flush_in *arg = (struct tmfs_flush_in *) inarg;
	struct tmfs_file_info fi;

	memset(&fi, 0, sizeof(fi));
	fi.fh = arg->fh;
	fi.fh_old = fi.fh;
	fi.flush = 1;
	if (req->f->conn.proto_minor >= 7)
		fi.lock_owner = arg->lock_owner;

	if (req->f->op.flush)
		req->f->op.flush(req, nodeid, &fi);
	else
		tmfs_reply_err(req, ENOSYS);
}

static void do_release(tmfs_req_t req, tmfs_ino_t nodeid, const void *inarg)
{
	struct tmfs_release_in *arg = (struct tmfs_release_in *) inarg;
	struct tmfs_file_info fi;

	memset(&fi, 0, sizeof(fi));
	fi.flags = arg->flags;
	fi.fh = arg->fh;
	fi.fh_old = fi.fh;
	if (req->f->conn.proto_minor >= 8) {
		fi.flush = (arg->release_flags & TMFS_RELEASE_FLUSH) ? 1 : 0;
		fi.lock_owner = arg->lock_owner;
	}
	if (arg->release_flags & TMFS_RELEASE_FLOCK_UNLOCK) {
		fi.flock_release = 1;
		fi.lock_owner = arg->lock_owner;
	}

	if (req->f->op.release)
		req->f->op.release(req, nodeid, &fi);
	else
		tmfs_reply_err(req, 0);
}

static void do_fsync(tmfs_req_t req, tmfs_ino_t nodeid, const void *inarg)
{
	struct tmfs_fsync_in *arg = (struct tmfs_fsync_in *) inarg;
	struct tmfs_file_info fi;

	memset(&fi, 0, sizeof(fi));
	fi.fh = arg->fh;
	fi.fh_old = fi.fh;

	if (req->f->op.fsync)
		req->f->op.fsync(req, nodeid, arg->fsync_flags & 1, &fi);
	else
		tmfs_reply_err(req, ENOSYS);
}

static void do_opendir(tmfs_req_t req, tmfs_ino_t nodeid, const void *inarg)
{
	struct tmfs_open_in *arg = (struct tmfs_open_in *) inarg;
	struct tmfs_file_info fi;

	memset(&fi, 0, sizeof(fi));
	fi.flags = arg->flags;

	if (req->f->op.opendir)
		req->f->op.opendir(req, nodeid, &fi);
	else
		tmfs_reply_open(req, &fi);
}

static void do_readdir(tmfs_req_t req, tmfs_ino_t nodeid, const void *inarg)
{
	struct tmfs_read_in *arg = (struct tmfs_read_in *) inarg;
	struct tmfs_file_info fi;

	memset(&fi, 0, sizeof(fi));
	fi.fh = arg->fh;
	fi.fh_old = fi.fh;

	if (req->f->op.readdir)
		req->f->op.readdir(req, nodeid, arg->size, arg->offset, &fi);
	else
		tmfs_reply_err(req, ENOSYS);
}

static void do_releasedir(tmfs_req_t req, tmfs_ino_t nodeid, const void *inarg)
{
	struct tmfs_release_in *arg = (struct tmfs_release_in *) inarg;
	struct tmfs_file_info fi;

	memset(&fi, 0, sizeof(fi));
	fi.flags = arg->flags;
	fi.fh = arg->fh;
	fi.fh_old = fi.fh;

	if (req->f->op.releasedir)
		req->f->op.releasedir(req, nodeid, &fi);
	else
		tmfs_reply_err(req, 0);
}

static void do_fsyncdir(tmfs_req_t req, tmfs_ino_t nodeid, const void *inarg)
{
	struct tmfs_fsync_in *arg = (struct tmfs_fsync_in *) inarg;
	struct tmfs_file_info fi;

	memset(&fi, 0, sizeof(fi));
	fi.fh = arg->fh;
	fi.fh_old = fi.fh;

	if (req->f->op.fsyncdir)
		req->f->op.fsyncdir(req, nodeid, arg->fsync_flags & 1, &fi);
	else
		tmfs_reply_err(req, ENOSYS);
}

static void do_statfs(tmfs_req_t req, tmfs_ino_t nodeid, const void *inarg)
{
	(void) nodeid;
	(void) inarg;

	if (req->f->op.statfs)
		req->f->op.statfs(req, nodeid);
	else {
		struct statvfs buf = {
			.f_namemax = 255,
			.f_bsize = 512,
		};
		tmfs_reply_statfs(req, &buf);
	}
}

static void do_setxattr(tmfs_req_t req, tmfs_ino_t nodeid, const void *inarg)
{
	struct tmfs_setxattr_in *arg = (struct tmfs_setxattr_in *) inarg;
	char *name = PARAM(arg);
	char *value = name + strlen(name) + 1;

	if (req->f->op.setxattr)
		req->f->op.setxattr(req, nodeid, name, value, arg->size,
				    arg->flags);
	else
		tmfs_reply_err(req, ENOSYS);
}

static void do_getxattr(tmfs_req_t req, tmfs_ino_t nodeid, const void *inarg)
{
	struct tmfs_getxattr_in *arg = (struct tmfs_getxattr_in *) inarg;

	if (req->f->op.getxattr)
		req->f->op.getxattr(req, nodeid, PARAM(arg), arg->size);
	else
		tmfs_reply_err(req, ENOSYS);
}

static void do_listxattr(tmfs_req_t req, tmfs_ino_t nodeid, const void *inarg)
{
	struct tmfs_getxattr_in *arg = (struct tmfs_getxattr_in *) inarg;

	if (req->f->op.listxattr)
		req->f->op.listxattr(req, nodeid, arg->size);
	else
		tmfs_reply_err(req, ENOSYS);
}

static void do_removexattr(tmfs_req_t req, tmfs_ino_t nodeid, const void *inarg)
{
	char *name = (char *) inarg;

	if (req->f->op.removexattr)
		req->f->op.removexattr(req, nodeid, name);
	else
		tmfs_reply_err(req, ENOSYS);
}

static void convert_tmfs_file_lock(struct tmfs_file_lock *fl,
				   struct flock *flock)
{
	memset(flock, 0, sizeof(struct flock));
	flock->l_type = fl->type;
	flock->l_whence = SEEK_SET;
	flock->l_start = fl->start;
	if (fl->end == OFFSET_MAX)
		flock->l_len = 0;
	else
		flock->l_len = fl->end - fl->start + 1;
	flock->l_pid = fl->pid;
}

static void do_getlk(tmfs_req_t req, tmfs_ino_t nodeid, const void *inarg)
{
	struct tmfs_lk_in *arg = (struct tmfs_lk_in *) inarg;
	struct tmfs_file_info fi;
	struct flock flock;

	memset(&fi, 0, sizeof(fi));
	fi.fh = arg->fh;
	fi.lock_owner = arg->owner;

	convert_tmfs_file_lock(&arg->lk, &flock);
	if (req->f->op.getlk)
		req->f->op.getlk(req, nodeid, &fi, &flock);
	else
		tmfs_reply_err(req, ENOSYS);
}

static void do_setlk_common(tmfs_req_t req, tmfs_ino_t nodeid,
			    const void *inarg, int sleep)
{
	struct tmfs_lk_in *arg = (struct tmfs_lk_in *) inarg;
	struct tmfs_file_info fi;
	struct flock flock;

	memset(&fi, 0, sizeof(fi));
	fi.fh = arg->fh;
	fi.lock_owner = arg->owner;

	if (arg->lk_flags & TMFS_LK_FLOCK) {
		int op = 0;

		switch (arg->lk.type) {
		case F_RDLCK:
			op = LOCK_SH;
			break;
		case F_WRLCK:
			op = LOCK_EX;
			break;
		case F_UNLCK:
			op = LOCK_UN;
			break;
		}
		if (!sleep)
			op |= LOCK_NB;

		if (req->f->op.flock)
			req->f->op.flock(req, nodeid, &fi, op);
		else
			tmfs_reply_err(req, ENOSYS);
	} else {
		convert_tmfs_file_lock(&arg->lk, &flock);
		if (req->f->op.setlk)
			req->f->op.setlk(req, nodeid, &fi, &flock, sleep);
		else
			tmfs_reply_err(req, ENOSYS);
	}
}

static void do_setlk(tmfs_req_t req, tmfs_ino_t nodeid, const void *inarg)
{
	do_setlk_common(req, nodeid, inarg, 0);
}

static void do_setlkw(tmfs_req_t req, tmfs_ino_t nodeid, const void *inarg)
{
	do_setlk_common(req, nodeid, inarg, 1);
}

static int find_interrupted(struct tmfs_ll *f, struct tmfs_req *req)
{
	struct tmfs_req *curr;

	for (curr = f->list.next; curr != &f->list; curr = curr->next) {
		if (curr->unique == req->u.i.unique) {
			tmfs_interrupt_func_t func;
			void *data;

			curr->ctr++;
			pthread_mutex_unlock(&f->lock);

			/* Ugh, ugly locking */
			pthread_mutex_lock(&curr->lock);
			pthread_mutex_lock(&f->lock);
			curr->interrupted = 1;
			func = curr->u.ni.func;
			data = curr->u.ni.data;
			pthread_mutex_unlock(&f->lock);
			if (func)
				func(curr, data);
			pthread_mutex_unlock(&curr->lock);

			pthread_mutex_lock(&f->lock);
			curr->ctr--;
			if (!curr->ctr)
				destroy_req(curr);

			return 1;
		}
	}
	for (curr = f->interrupts.next; curr != &f->interrupts;
	     curr = curr->next) {
		if (curr->u.i.unique == req->u.i.unique)
			return 1;
	}
	return 0;
}

static void do_interrupt(tmfs_req_t req, tmfs_ino_t nodeid, const void *inarg)
{
	struct tmfs_interrupt_in *arg = (struct tmfs_interrupt_in *) inarg;
	struct tmfs_ll *f = req->f;

	(void) nodeid;
	if (f->debug)
		fprintf(stderr, "INTERRUPT: %llu\n",
			(unsigned long long) arg->unique);

	req->u.i.unique = arg->unique;

	pthread_mutex_lock(&f->lock);
	if (find_interrupted(f, req))
		destroy_req(req);
	else
		list_add_req(req, &f->interrupts);
	pthread_mutex_unlock(&f->lock);
}

static struct tmfs_req *check_interrupt(struct tmfs_ll *f, struct tmfs_req *req)
{
	struct tmfs_req *curr;

	for (curr = f->interrupts.next; curr != &f->interrupts;
	     curr = curr->next) {
		if (curr->u.i.unique == req->unique) {
			req->interrupted = 1;
			list_del_req(curr);
			free(curr);
			return NULL;
		}
	}
	curr = f->interrupts.next;
	if (curr != &f->interrupts) {
		list_del_req(curr);
		list_init_req(curr);
		return curr;
	} else
		return NULL;
}

static void do_bmap(tmfs_req_t req, tmfs_ino_t nodeid, const void *inarg)
{
	struct tmfs_bmap_in *arg = (struct tmfs_bmap_in *) inarg;

	if (req->f->op.bmap)
		req->f->op.bmap(req, nodeid, arg->blocksize, arg->block);
	else
		tmfs_reply_err(req, ENOSYS);
}

static void do_ioctl(tmfs_req_t req, tmfs_ino_t nodeid, const void *inarg)
{
	struct tmfs_ioctl_in *arg = (struct tmfs_ioctl_in *) inarg;
	unsigned int flags = arg->flags;
	void *in_buf = arg->in_size ? PARAM(arg) : NULL;
	struct tmfs_file_info fi;

	if (flags & TMFS_IOCTL_DIR &&
	    !(req->f->conn.want & TMFS_CAP_IOCTL_DIR)) {
		tmfs_reply_err(req, ENOTTY);
		return;
	}

	memset(&fi, 0, sizeof(fi));
	fi.fh = arg->fh;
	fi.fh_old = fi.fh;

	if (sizeof(void *) == 4 && req->f->conn.proto_minor >= 16 &&
	    !(flags & TMFS_IOCTL_32BIT)) {
		req->ioctl_64bit = 1;
	}

	if (req->f->op.ioctl)
		req->f->op.ioctl(req, nodeid, arg->cmd,
				 (void *)(uintptr_t)arg->arg, &fi, flags,
				 in_buf, arg->in_size, arg->out_size);
	else
		tmfs_reply_err(req, ENOSYS);
}

void tmfs_pollhandle_destroy(struct tmfs_pollhandle *ph)
{
	free(ph);
}

static void do_poll(tmfs_req_t req, tmfs_ino_t nodeid, const void *inarg)
{
	struct tmfs_poll_in *arg = (struct tmfs_poll_in *) inarg;
	struct tmfs_file_info fi;

	memset(&fi, 0, sizeof(fi));
	fi.fh = arg->fh;
	fi.fh_old = fi.fh;

	if (req->f->op.poll) {
		struct tmfs_pollhandle *ph = NULL;

		if (arg->flags & TMFS_POLL_SCHEDULE_NOTIFY) {
			ph = malloc(sizeof(struct tmfs_pollhandle));
			if (ph == NULL) {
				tmfs_reply_err(req, ENOMEM);
				return;
			}
			ph->kh = arg->kh;
			ph->ch = req->ch;
			ph->f = req->f;
		}

		req->f->op.poll(req, nodeid, &fi, ph);
	} else {
		tmfs_reply_err(req, ENOSYS);
	}
}

static void do_fallocate(tmfs_req_t req, tmfs_ino_t nodeid, const void *inarg)
{
	struct tmfs_fallocate_in *arg = (struct tmfs_fallocate_in *) inarg;
	struct tmfs_file_info fi;

	memset(&fi, 0, sizeof(fi));
	fi.fh = arg->fh;

	if (req->f->op.fallocate)
		req->f->op.fallocate(req, nodeid, arg->mode, arg->offset, arg->length, &fi);
	else
		tmfs_reply_err(req, ENOSYS);
}

static void do_init(tmfs_req_t req, tmfs_ino_t nodeid, const void *inarg)
{
	struct tmfs_init_in *arg = (struct tmfs_init_in *) inarg;
	struct tmfs_init_out outarg;
	struct tmfs_ll *f = req->f;
	size_t bufsize = tmfs_chan_bufsize(req->ch);

	(void) nodeid;
	if (f->debug) {
		fprintf(stderr, "INIT: %u.%u\n", arg->major, arg->minor);
		if (arg->major == 7 && arg->minor >= 6) {
			fprintf(stderr, "flags=0x%08x\n", arg->flags);
			fprintf(stderr, "max_readahead=0x%08x\n",
				arg->max_readahead);
		}
	}
	f->conn.proto_major = arg->major;
	f->conn.proto_minor = arg->minor;
	f->conn.capable = 0;
	f->conn.want = 0;

	memset(&outarg, 0, sizeof(outarg));
	outarg.major = TMFS_KERNEL_VERSION;
	outarg.minor = TMFS_KERNEL_MINOR_VERSION;

	if (arg->major < 7) {
		fprintf(stderr, "tmfs: unsupported protocol version: %u.%u\n",
			arg->major, arg->minor);
		tmfs_reply_err(req, EPROTO);
		return;
	}

	if (arg->major > 7) {
		/* Wait for a second INIT request with a 7.X version */
		send_reply_ok(req, &outarg, sizeof(outarg));
		return;
	}

	if (arg->minor >= 6) {
		if (f->conn.async_read)
			f->conn.async_read = arg->flags & TMFS_ASYNC_READ;
		if (arg->max_readahead < f->conn.max_readahead)
			f->conn.max_readahead = arg->max_readahead;
		if (arg->flags & TMFS_ASYNC_READ)
			f->conn.capable |= TMFS_CAP_ASYNC_READ;
		if (arg->flags & TMFS_POSIX_LOCKS)
			f->conn.capable |= TMFS_CAP_POSIX_LOCKS;
		if (arg->flags & TMFS_ATOMIC_O_TRUNC)
			f->conn.capable |= TMFS_CAP_ATOMIC_O_TRUNC;
		if (arg->flags & TMFS_EXPORT_SUPPORT)
			f->conn.capable |= TMFS_CAP_EXPORT_SUPPORT;
		if (arg->flags & TMFS_BIG_WRITES)
			f->conn.capable |= TMFS_CAP_BIG_WRITES;
		if (arg->flags & TMFS_DONT_MASK)
			f->conn.capable |= TMFS_CAP_DONT_MASK;
		if (arg->flags & TMFS_FLOCK_LOCKS)
			f->conn.capable |= TMFS_CAP_FLOCK_LOCKS;
	} else {
		f->conn.async_read = 0;
		f->conn.max_readahead = 0;
	}

	if (req->f->conn.proto_minor >= 14) {
#ifdef HAVE_SPLICE
#ifdef HAVE_VMSPLICE
		f->conn.capable |= TMFS_CAP_SPLICE_WRITE | TMFS_CAP_SPLICE_MOVE;
		if (f->splice_write)
			f->conn.want |= TMFS_CAP_SPLICE_WRITE;
		if (f->splice_move)
			f->conn.want |= TMFS_CAP_SPLICE_MOVE;
#endif
		f->conn.capable |= TMFS_CAP_SPLICE_READ;
		if (f->splice_read)
			f->conn.want |= TMFS_CAP_SPLICE_READ;
#endif
	}
	if (req->f->conn.proto_minor >= 18)
		f->conn.capable |= TMFS_CAP_IOCTL_DIR;

	if (f->atomic_o_trunc)
		f->conn.want |= TMFS_CAP_ATOMIC_O_TRUNC;
	if (f->op.getlk && f->op.setlk && !f->no_remote_posix_lock)
		f->conn.want |= TMFS_CAP_POSIX_LOCKS;
	if (f->op.flock && !f->no_remote_flock)
		f->conn.want |= TMFS_CAP_FLOCK_LOCKS;
	if (f->big_writes)
		f->conn.want |= TMFS_CAP_BIG_WRITES;

	if (bufsize < TMFS_MIN_READ_BUFFER) {
		fprintf(stderr, "tmfs: warning: buffer size too small: %zu\n",
			bufsize);
		bufsize = TMFS_MIN_READ_BUFFER;
	}

	bufsize -= 4096;
	if (bufsize < f->conn.max_write)
		f->conn.max_write = bufsize;

	f->got_init = 1;
	if (f->op.init)
		f->op.init(f->userdata, &f->conn);

	if (f->no_splice_read)
		f->conn.want &= ~TMFS_CAP_SPLICE_READ;
	if (f->no_splice_write)
		f->conn.want &= ~TMFS_CAP_SPLICE_WRITE;
	if (f->no_splice_move)
		f->conn.want &= ~TMFS_CAP_SPLICE_MOVE;

	if (f->conn.async_read || (f->conn.want & TMFS_CAP_ASYNC_READ))
		outarg.flags |= TMFS_ASYNC_READ;
	if (f->conn.want & TMFS_CAP_POSIX_LOCKS)
		outarg.flags |= TMFS_POSIX_LOCKS;
	if (f->conn.want & TMFS_CAP_ATOMIC_O_TRUNC)
		outarg.flags |= TMFS_ATOMIC_O_TRUNC;
	if (f->conn.want & TMFS_CAP_EXPORT_SUPPORT)
		outarg.flags |= TMFS_EXPORT_SUPPORT;
	if (f->conn.want & TMFS_CAP_BIG_WRITES)
		outarg.flags |= TMFS_BIG_WRITES;
	if (f->conn.want & TMFS_CAP_DONT_MASK)
		outarg.flags |= TMFS_DONT_MASK;
	if (f->conn.want & TMFS_CAP_FLOCK_LOCKS)
		outarg.flags |= TMFS_FLOCK_LOCKS;
	outarg.max_readahead = f->conn.max_readahead;
	outarg.max_write = f->conn.max_write;
	if (f->conn.proto_minor >= 13) {
		if (f->conn.max_background >= (1 << 16))
			f->conn.max_background = (1 << 16) - 1;
		if (f->conn.congestion_threshold > f->conn.max_background)
			f->conn.congestion_threshold = f->conn.max_background;
		if (!f->conn.congestion_threshold) {
			f->conn.congestion_threshold =
				f->conn.max_background * 3 / 4;
		}

		outarg.max_background = f->conn.max_background;
		outarg.congestion_threshold = f->conn.congestion_threshold;
	}

	if (f->debug) {
		fprintf(stderr, "   INIT: %u.%u\n", outarg.major, outarg.minor);
		fprintf(stderr, "   flags=0x%08x\n", outarg.flags);
		fprintf(stderr, "   max_readahead=0x%08x\n",
			outarg.max_readahead);
		fprintf(stderr, "   max_write=0x%08x\n", outarg.max_write);
		fprintf(stderr, "   max_background=%i\n",
			outarg.max_background);
		fprintf(stderr, "   congestion_threshold=%i\n",
		        outarg.congestion_threshold);
	}

	send_reply_ok(req, &outarg, arg->minor < 5 ? 8 : sizeof(outarg));
}

static void do_destroy(tmfs_req_t req, tmfs_ino_t nodeid, const void *inarg)
{
	struct tmfs_ll *f = req->f;

	(void) nodeid;
	(void) inarg;

	f->got_destroy = 1;
	if (f->op.destroy)
		f->op.destroy(f->userdata);

	send_reply_ok(req, NULL, 0);
}

static void list_del_nreq(struct tmfs_notify_req *nreq)
{
	struct tmfs_notify_req *prev = nreq->prev;
	struct tmfs_notify_req *next = nreq->next;
	prev->next = next;
	next->prev = prev;
}

static void list_add_nreq(struct tmfs_notify_req *nreq,
			  struct tmfs_notify_req *next)
{
	struct tmfs_notify_req *prev = next->prev;
	nreq->next = next;
	nreq->prev = prev;
	prev->next = nreq;
	next->prev = nreq;
}

static void list_init_nreq(struct tmfs_notify_req *nreq)
{
	nreq->next = nreq;
	nreq->prev = nreq;
}

static void do_notify_reply(tmfs_req_t req, tmfs_ino_t nodeid,
			    const void *inarg, const struct tmfs_buf *buf)
{
	struct tmfs_ll *f = req->f;
	struct tmfs_notify_req *nreq;
	struct tmfs_notify_req *head;

	pthread_mutex_lock(&f->lock);
	head = &f->notify_list;
	for (nreq = head->next; nreq != head; nreq = nreq->next) {
		if (nreq->unique == req->unique) {
			list_del_nreq(nreq);
			break;
		}
	}
	pthread_mutex_unlock(&f->lock);

	if (nreq != head)
		nreq->reply(nreq, req, nodeid, inarg, buf);
}

static int send_notify_iov(struct tmfs_ll *f, struct tmfs_chan *ch,
			   int notify_code, struct iovec *iov, int count)
{
	struct tmfs_out_header out;

	if (!f->got_init)
		return -ENOTCONN;

	out.unique = 0;
	out.error = notify_code;
	iov[0].iov_base = &out;
	iov[0].iov_len = sizeof(struct tmfs_out_header);

	return tmfs_send_msg(f, ch, iov, count);
}

int tmfs_lowlevel_notify_poll(struct tmfs_pollhandle *ph)
{
	if (ph != NULL) {
		struct tmfs_notify_poll_wakeup_out outarg;
		struct iovec iov[2];

		outarg.kh = ph->kh;

		iov[1].iov_base = &outarg;
		iov[1].iov_len = sizeof(outarg);

		return send_notify_iov(ph->f, ph->ch, TMFS_NOTIFY_POLL, iov, 2);
	} else {
		return 0;
	}
}

int tmfs_lowlevel_notify_inval_inode(struct tmfs_chan *ch, tmfs_ino_t ino,
                                     off_t off, off_t len)
{
	struct tmfs_notify_inval_inode_out outarg;
	struct tmfs_ll *f;
	struct iovec iov[2];

	if (!ch)
		return -EINVAL;

	f = (struct tmfs_ll *)tmfs_session_data(tmfs_chan_session(ch));
	if (!f)
		return -ENODEV;

	outarg.ino = ino;
	outarg.off = off;
	outarg.len = len;

	iov[1].iov_base = &outarg;
	iov[1].iov_len = sizeof(outarg);

	return send_notify_iov(f, ch, TMFS_NOTIFY_INVAL_INODE, iov, 2);
}

int tmfs_lowlevel_notify_inval_entry(struct tmfs_chan *ch, tmfs_ino_t parent,
                                     const char *name, size_t namelen)
{
	struct tmfs_notify_inval_entry_out outarg;
	struct tmfs_ll *f;
	struct iovec iov[3];

	if (!ch)
		return -EINVAL;

	f = (struct tmfs_ll *)tmfs_session_data(tmfs_chan_session(ch));
	if (!f)
		return -ENODEV;

	outarg.parent = parent;
	outarg.namelen = namelen;
	outarg.padding = 0;

	iov[1].iov_base = &outarg;
	iov[1].iov_len = sizeof(outarg);
	iov[2].iov_base = (void *)name;
	iov[2].iov_len = namelen + 1;

	return send_notify_iov(f, ch, TMFS_NOTIFY_INVAL_ENTRY, iov, 3);
}

int tmfs_lowlevel_notify_delete(struct tmfs_chan *ch,
				tmfs_ino_t parent, tmfs_ino_t child,
				const char *name, size_t namelen)
{
	struct tmfs_notify_delete_out outarg;
	struct tmfs_ll *f;
	struct iovec iov[3];

	if (!ch)
		return -EINVAL;

	f = (struct tmfs_ll *)tmfs_session_data(tmfs_chan_session(ch));
	if (!f)
		return -ENODEV;

	if (f->conn.proto_minor < 18)
		return -ENOSYS;

	outarg.parent = parent;
	outarg.child = child;
	outarg.namelen = namelen;
	outarg.padding = 0;

	iov[1].iov_base = &outarg;
	iov[1].iov_len = sizeof(outarg);
	iov[2].iov_base = (void *)name;
	iov[2].iov_len = namelen + 1;

	return send_notify_iov(f, ch, TMFS_NOTIFY_DELETE, iov, 3);
}

int tmfs_lowlevel_notify_store(struct tmfs_chan *ch, tmfs_ino_t ino,
			       off_t offset, struct tmfs_bufvec *bufv,
			       enum tmfs_buf_copy_flags flags)
{
	struct tmfs_out_header out;
	struct tmfs_notify_store_out outarg;
	struct tmfs_ll *f;
	struct iovec iov[3];
	size_t size = tmfs_buf_size(bufv);
	int res;

	if (!ch)
		return -EINVAL;

	f = (struct tmfs_ll *)tmfs_session_data(tmfs_chan_session(ch));
	if (!f)
		return -ENODEV;

	if (f->conn.proto_minor < 15)
		return -ENOSYS;

	out.unique = 0;
	out.error = TMFS_NOTIFY_STORE;

	outarg.nodeid = ino;
	outarg.offset = offset;
	outarg.size = size;

	iov[0].iov_base = &out;
	iov[0].iov_len = sizeof(out);
	iov[1].iov_base = &outarg;
	iov[1].iov_len = sizeof(outarg);

	res = tmfs_send_data_iov(f, ch, iov, 2, bufv, flags);
	if (res > 0)
		res = -res;

	return res;
}

struct tmfs_retrieve_req {
	struct tmfs_notify_req nreq;
	void *cookie;
};

static void tmfs_ll_retrieve_reply(struct tmfs_notify_req *nreq,
				   tmfs_req_t req, tmfs_ino_t ino,
				   const void *inarg,
				   const struct tmfs_buf *ibuf)
{
	struct tmfs_ll *f = req->f;
	struct tmfs_retrieve_req *rreq =
		container_of(nreq, struct tmfs_retrieve_req, nreq);
	const struct tmfs_notify_retrieve_in *arg = inarg;
	struct tmfs_bufvec bufv = {
		.buf[0] = *ibuf,
		.count = 1,
	};

	if (!(bufv.buf[0].flags & TMFS_BUF_IS_FD))
		bufv.buf[0].mem = PARAM(arg);

	bufv.buf[0].size -= sizeof(struct tmfs_in_header) +
		sizeof(struct tmfs_notify_retrieve_in);

	if (bufv.buf[0].size < arg->size) {
		fprintf(stderr, "tmfs: retrieve reply: buffer size too small\n");
		tmfs_reply_none(req);
		goto out;
	}
	bufv.buf[0].size = arg->size;

	if (req->f->op.retrieve_reply) {
		req->f->op.retrieve_reply(req, rreq->cookie, ino,
					  arg->offset, &bufv);
	} else {
		tmfs_reply_none(req);
	}
out:
	free(rreq);
	if ((ibuf->flags & TMFS_BUF_IS_FD) && bufv.idx < bufv.count)
		tmfs_ll_clear_pipe(f);
}

int tmfs_lowlevel_notify_retrieve(struct tmfs_chan *ch, tmfs_ino_t ino,
				  size_t size, off_t offset, void *cookie)
{
	struct tmfs_notify_retrieve_out outarg;
	struct tmfs_ll *f;
	struct iovec iov[2];
	struct tmfs_retrieve_req *rreq;
	int err;

	if (!ch)
		return -EINVAL;

	f = (struct tmfs_ll *)tmfs_session_data(tmfs_chan_session(ch));
	if (!f)
		return -ENODEV;

	if (f->conn.proto_minor < 15)
		return -ENOSYS;

	rreq = malloc(sizeof(*rreq));
	if (rreq == NULL)
		return -ENOMEM;

	pthread_mutex_lock(&f->lock);
	rreq->cookie = cookie;
	rreq->nreq.unique = f->notify_ctr++;
	rreq->nreq.reply = tmfs_ll_retrieve_reply;
	list_add_nreq(&rreq->nreq, &f->notify_list);
	pthread_mutex_unlock(&f->lock);

	outarg.notify_unique = rreq->nreq.unique;
	outarg.nodeid = ino;
	outarg.offset = offset;
	outarg.size = size;

	iov[1].iov_base = &outarg;
	iov[1].iov_len = sizeof(outarg);

	err = send_notify_iov(f, ch, TMFS_NOTIFY_RETRIEVE, iov, 2);
	if (err) {
		pthread_mutex_lock(&f->lock);
		list_del_nreq(&rreq->nreq);
		pthread_mutex_unlock(&f->lock);
		free(rreq);
	}

	return err;
}

void *tmfs_req_userdata(tmfs_req_t req)
{
	return req->f->userdata;
}

const struct tmfs_ctx *tmfs_req_ctx(tmfs_req_t req)
{
	return &req->ctx;
}

/*
 * The size of tmfs_ctx got extended, so need to be careful about
 * incompatibility (i.e. a new binary cannot work with an old
 * library).
 */
const struct tmfs_ctx *tmfs_req_ctx_compat24(tmfs_req_t req);
const struct tmfs_ctx *tmfs_req_ctx_compat24(tmfs_req_t req)
{
	return tmfs_req_ctx(req);
}
#ifndef __NetBSD__
TMFS_SYMVER(".symver tmfs_req_ctx_compat24,tmfs_req_ctx@TMFS_2.4");
#endif


void tmfs_req_interrupt_func(tmfs_req_t req, tmfs_interrupt_func_t func,
			     void *data)
{
	pthread_mutex_lock(&req->lock);
	pthread_mutex_lock(&req->f->lock);
	req->u.ni.func = func;
	req->u.ni.data = data;
	pthread_mutex_unlock(&req->f->lock);
	if (req->interrupted && func)
		func(req, data);
	pthread_mutex_unlock(&req->lock);
}

int tmfs_req_interrupted(tmfs_req_t req)
{
	int interrupted;

	pthread_mutex_lock(&req->f->lock);
	interrupted = req->interrupted;
	pthread_mutex_unlock(&req->f->lock);

	return interrupted;
}

static struct {
	void (*func)(tmfs_req_t, tmfs_ino_t, const void *);
	const char *name;
} tmfs_ll_ops[] = {
	[TMFS_LOOKUP]	   = { do_lookup,      "LOOKUP"	     },
	[TMFS_FORGET]	   = { do_forget,      "FORGET"	     },
	[TMFS_GETATTR]	   = { do_getattr,     "GETATTR"     },
	[TMFS_SETATTR]	   = { do_setattr,     "SETATTR"     },
	[TMFS_READLINK]	   = { do_readlink,    "READLINK"    },
	[TMFS_SYMLINK]	   = { do_symlink,     "SYMLINK"     },
	[TMFS_MKNOD]	   = { do_mknod,       "MKNOD"	     },
	[TMFS_MKDIR]	   = { do_mkdir,       "MKDIR"	     },
	[TMFS_UNLINK]	   = { do_unlink,      "UNLINK"	     },
	[TMFS_RMDIR]	   = { do_rmdir,       "RMDIR"	     },
	[TMFS_RENAME]	   = { do_rename,      "RENAME"	     },
	[TMFS_LINK]	   = { do_link,	       "LINK"	     },
	[TMFS_OPEN]	   = { do_open,	       "OPEN"	     },
	[TMFS_READ]	   = { do_read,	       "READ"	     },
	[TMFS_WRITE]	   = { do_write,       "WRITE"	     },
	[TMFS_STATFS]	   = { do_statfs,      "STATFS"	     },
	[TMFS_RELEASE]	   = { do_release,     "RELEASE"     },
	[TMFS_FSYNC]	   = { do_fsync,       "FSYNC"	     },
	[TMFS_SETXATTR]	   = { do_setxattr,    "SETXATTR"    },
	[TMFS_GETXATTR]	   = { do_getxattr,    "GETXATTR"    },
	[TMFS_LISTXATTR]   = { do_listxattr,   "LISTXATTR"   },
	[TMFS_REMOVEXATTR] = { do_removexattr, "REMOVEXATTR" },
	[TMFS_FLUSH]	   = { do_flush,       "FLUSH"	     },
	[TMFS_INIT]	   = { do_init,	       "INIT"	     },
	[TMFS_OPENDIR]	   = { do_opendir,     "OPENDIR"     },
	[TMFS_READDIR]	   = { do_readdir,     "READDIR"     },
	[TMFS_RELEASEDIR]  = { do_releasedir,  "RELEASEDIR"  },
	[TMFS_FSYNCDIR]	   = { do_fsyncdir,    "FSYNCDIR"    },
	[TMFS_GETLK]	   = { do_getlk,       "GETLK"	     },
	[TMFS_SETLK]	   = { do_setlk,       "SETLK"	     },
	[TMFS_SETLKW]	   = { do_setlkw,      "SETLKW"	     },
	[TMFS_ACCESS]	   = { do_access,      "ACCESS"	     },
	[TMFS_CREATE]	   = { do_create,      "CREATE"	     },
	[TMFS_INTERRUPT]   = { do_interrupt,   "INTERRUPT"   },
	[TMFS_BMAP]	   = { do_bmap,	       "BMAP"	     },
	[TMFS_IOCTL]	   = { do_ioctl,       "IOCTL"	     },
	[TMFS_POLL]	   = { do_poll,        "POLL"	     },
	[TMFS_FALLOCATE]   = { do_fallocate,   "FALLOCATE"   },
	[TMFS_DESTROY]	   = { do_destroy,     "DESTROY"     },
	[TMFS_NOTIFY_REPLY] = { (void *) 1,    "NOTIFY_REPLY" },
	[TMFS_BATCH_FORGET] = { do_batch_forget, "BATCH_FORGET" },
	[TMCD_INIT]	   = { tmcd_lowlevel_init, "TMCD_INIT"   },
};

#define TMFS_MAXOP (sizeof(tmfs_ll_ops) / sizeof(tmfs_ll_ops[0]))

static const char *opname(enum tmfs_opcode opcode)
{
	if (opcode >= TMFS_MAXOP || !tmfs_ll_ops[opcode].name)
		return "???";
	else
		return tmfs_ll_ops[opcode].name;
}

static int tmfs_ll_copy_from_pipe(struct tmfs_bufvec *dst,
				  struct tmfs_bufvec *src)
{
	int res = tmfs_buf_copy(dst, src, 0);
	if (res < 0) {
		fprintf(stderr, "tmfs: copy from pipe: %s\n", strerror(-res));
		return res;
	}
	if (res < tmfs_buf_size(dst)) {
		fprintf(stderr, "tmfs: copy from pipe: short read\n");
		return -1;
	}
	return 0;
}

static void tmfs_ll_process_buf(void *data, const struct tmfs_buf *buf,
				struct tmfs_chan *ch)
{
	struct tmfs_ll *f = (struct tmfs_ll *) data;
	const size_t write_header_size = sizeof(struct tmfs_in_header) +
		sizeof(struct tmfs_write_in);
	struct tmfs_bufvec bufv = { .buf[0] = *buf, .count = 1 };
	struct tmfs_bufvec tmpbuf = TMFS_BUFVEC_INIT(write_header_size);
	struct tmfs_in_header *in;
	const void *inarg;
	struct tmfs_req *req;
	void *mbuf = NULL;
	int err;
	int res;

	if (buf->flags & TMFS_BUF_IS_FD) {
		if (buf->size < tmpbuf.buf[0].size)
			tmpbuf.buf[0].size = buf->size;

		mbuf = malloc(tmpbuf.buf[0].size);
		if (mbuf == NULL) {
			fprintf(stderr, "tmfs: failed to allocate header\n");
			goto clear_pipe;
		}
		tmpbuf.buf[0].mem = mbuf;

		res = tmfs_ll_copy_from_pipe(&tmpbuf, &bufv);
		if (res < 0)
			goto clear_pipe;

		in = mbuf;
	} else {
		in = buf->mem;
	}

	if (f->debug) {
		fprintf(stderr,
			"unique: %llu, opcode: %s (%i), nodeid: %lu, insize: %zu, pid: %u\n",
			(unsigned long long) in->unique,
			opname((enum tmfs_opcode) in->opcode), in->opcode,
			(unsigned long) in->nodeid, buf->size, in->pid);
	}

	req = tmfs_ll_alloc_req(f);
	if (req == NULL) {
		struct tmfs_out_header out = {
			.unique = in->unique,
			.error = -ENOMEM,
		};
		struct iovec iov = {
			.iov_base = &out,
			.iov_len = sizeof(struct tmfs_out_header),
		};

		tmfs_send_msg(f, ch, &iov, 1);
		goto clear_pipe;
	}

	req->unique = in->unique;
	req->ctx.uid = in->uid;
	req->ctx.gid = in->gid;
	req->ctx.pid = in->pid;
	req->ch = ch;

	err = EIO;
	if (!f->got_init) {
		enum tmfs_opcode expected;

		expected = f->tmcd_data ? TMCD_INIT : TMFS_INIT;
		if (in->opcode != expected)
			goto reply_err;
	} else if (in->opcode == TMFS_INIT || in->opcode == TMCD_INIT)
		goto reply_err;

	err = EACCES;
	if (f->allow_root && in->uid != f->owner && in->uid != 0 &&
		 in->opcode != TMFS_INIT && in->opcode != TMFS_READ &&
		 in->opcode != TMFS_WRITE && in->opcode != TMFS_FSYNC &&
		 in->opcode != TMFS_RELEASE && in->opcode != TMFS_READDIR &&
		 in->opcode != TMFS_FSYNCDIR && in->opcode != TMFS_RELEASEDIR &&
		 in->opcode != TMFS_NOTIFY_REPLY)
		goto reply_err;

	err = ENOSYS;
	if (in->opcode >= TMFS_MAXOP || !tmfs_ll_ops[in->opcode].func)
		goto reply_err;
	if (in->opcode != TMFS_INTERRUPT) {
		struct tmfs_req *intr;
		pthread_mutex_lock(&f->lock);
		intr = check_interrupt(f, req);
		list_add_req(req, &f->list);
		pthread_mutex_unlock(&f->lock);
		if (intr)
			tmfs_reply_err(intr, EAGAIN);
	}

	if ((buf->flags & TMFS_BUF_IS_FD) && write_header_size < buf->size &&
	    (in->opcode != TMFS_WRITE || !f->op.write_buf) &&
	    in->opcode != TMFS_NOTIFY_REPLY) {
		void *newmbuf;

		err = ENOMEM;
		newmbuf = realloc(mbuf, buf->size);
		if (newmbuf == NULL)
			goto reply_err;
		mbuf = newmbuf;

		tmpbuf = TMFS_BUFVEC_INIT(buf->size - write_header_size);
		tmpbuf.buf[0].mem = mbuf + write_header_size;

		res = tmfs_ll_copy_from_pipe(&tmpbuf, &bufv);
		err = -res;
		if (res < 0)
			goto reply_err;

		in = mbuf;
	}

	inarg = (void *) &in[1];
	if (in->opcode == TMFS_WRITE && f->op.write_buf)
		do_write_buf(req, in->nodeid, inarg, buf);
	else if (in->opcode == TMFS_NOTIFY_REPLY)
		do_notify_reply(req, in->nodeid, inarg, buf);
	else
		tmfs_ll_ops[in->opcode].func(req, in->nodeid, inarg);

out_free:
	free(mbuf);
	return;

reply_err:
	tmfs_reply_err(req, err);
clear_pipe:
	if (buf->flags & TMFS_BUF_IS_FD)
		tmfs_ll_clear_pipe(f);
	goto out_free;
}

static void tmfs_ll_process(void *data, const char *buf, size_t len,
			    struct tmfs_chan *ch)
{
	struct tmfs_buf fbuf = {
		.mem = (void *) buf,
		.size = len,
	};

	tmfs_ll_process_buf(data, &fbuf, ch);
}

enum {
	KEY_HELP,
	KEY_VERSION,
};

static const struct tmfs_opt tmfs_ll_opts[] = {
	{ "debug", offsetof(struct tmfs_ll, debug), 1 },
	{ "-d", offsetof(struct tmfs_ll, debug), 1 },
	{ "allow_root", offsetof(struct tmfs_ll, allow_root), 1 },
	{ "max_write=%u", offsetof(struct tmfs_ll, conn.max_write), 0 },
	{ "max_readahead=%u", offsetof(struct tmfs_ll, conn.max_readahead), 0 },
	{ "max_background=%u", offsetof(struct tmfs_ll, conn.max_background), 0 },
	{ "congestion_threshold=%u",
	  offsetof(struct tmfs_ll, conn.congestion_threshold), 0 },
	{ "async_read", offsetof(struct tmfs_ll, conn.async_read), 1 },
	{ "sync_read", offsetof(struct tmfs_ll, conn.async_read), 0 },
	{ "atomic_o_trunc", offsetof(struct tmfs_ll, atomic_o_trunc), 1},
	{ "no_remote_lock", offsetof(struct tmfs_ll, no_remote_posix_lock), 1},
	{ "no_remote_lock", offsetof(struct tmfs_ll, no_remote_flock), 1},
	{ "no_remote_flock", offsetof(struct tmfs_ll, no_remote_flock), 1},
	{ "no_remote_posix_lock", offsetof(struct tmfs_ll, no_remote_posix_lock), 1},
	{ "big_writes", offsetof(struct tmfs_ll, big_writes), 1},
	{ "splice_write", offsetof(struct tmfs_ll, splice_write), 1},
	{ "no_splice_write", offsetof(struct tmfs_ll, no_splice_write), 1},
	{ "splice_move", offsetof(struct tmfs_ll, splice_move), 1},
	{ "no_splice_move", offsetof(struct tmfs_ll, no_splice_move), 1},
	{ "splice_read", offsetof(struct tmfs_ll, splice_read), 1},
	{ "no_splice_read", offsetof(struct tmfs_ll, no_splice_read), 1},
	TMFS_OPT_KEY("max_read=", TMFS_OPT_KEY_DISCARD),
	TMFS_OPT_KEY("-h", KEY_HELP),
	TMFS_OPT_KEY("--help", KEY_HELP),
	TMFS_OPT_KEY("-V", KEY_VERSION),
	TMFS_OPT_KEY("--version", KEY_VERSION),
	TMFS_OPT_END
};

static void tmfs_ll_version(void)
{
	fprintf(stderr, "using TMFS kernel interface version %i.%i\n",
		TMFS_KERNEL_VERSION, TMFS_KERNEL_MINOR_VERSION);
}

static void tmfs_ll_help(void)
{
	fprintf(stderr,
"    -o max_write=N         set maximum size of write requests\n"
"    -o max_readahead=N     set maximum readahead\n"
"    -o max_background=N    set number of maximum background requests\n"
"    -o congestion_threshold=N  set kernel's congestion threshold\n"
"    -o async_read          perform reads asynchronously (default)\n"
"    -o sync_read           perform reads synchronously\n"
"    -o atomic_o_trunc      enable atomic open+truncate support\n"
"    -o big_writes          enable larger than 4kB writes\n"
"    -o no_remote_lock      disable remote file locking\n"
"    -o no_remote_flock     disable remote file locking (BSD)\n"
"    -o no_remote_posix_lock disable remove file locking (POSIX)\n"
"    -o [no_]splice_write   use splice to write to the tmfs device\n"
"    -o [no_]splice_move    move data while splicing to the tmfs device\n"
"    -o [no_]splice_read    use splice to read from the tmfs device\n"
);
}

static int tmfs_ll_opt_proc(void *data, const char *arg, int key,
			    struct tmfs_args *outargs)
{
	(void) data; (void) outargs;

	switch (key) {
	case KEY_HELP:
		tmfs_ll_help();
		break;

	case KEY_VERSION:
		tmfs_ll_version();
		break;

	default:
		fprintf(stderr, "tmfs: unknown option `%s'\n", arg);
	}

	return -1;
}

int tmfs_lowlevel_is_lib_option(const char *opt)
{
	return tmfs_opt_match(tmfs_ll_opts, opt);
}

static void tmfs_ll_destroy(void *data)
{
	struct tmfs_ll *f = (struct tmfs_ll *) data;
	struct tmfs_ll_pipe *llp;

	if (f->got_init && !f->got_destroy) {
		if (f->op.destroy)
			f->op.destroy(f->userdata);
	}
	llp = pthread_getspecific(f->pipe_key);
	if (llp != NULL)
		tmfs_ll_pipe_free(llp);
	pthread_key_delete(f->pipe_key);
	pthread_mutex_destroy(&f->lock);
	free(f->tmcd_data);
	free(f);
}

static void tmfs_ll_pipe_destructor(void *data)
{
	struct tmfs_ll_pipe *llp = data;
	tmfs_ll_pipe_free(llp);
}

#ifdef HAVE_SPLICE
static int tmfs_ll_receive_buf(struct tmfs_session *se, struct tmfs_buf *buf,
			       struct tmfs_chan **chp)
{
	struct tmfs_chan *ch = *chp;
	struct tmfs_ll *f = tmfs_session_data(se);
	size_t bufsize = buf->size;
	struct tmfs_ll_pipe *llp;
	struct tmfs_buf tmpbuf;
	int err;
	int res;

	if (f->conn.proto_minor < 14 || !(f->conn.want & TMFS_CAP_SPLICE_READ))
		goto fallback;

	llp = tmfs_ll_get_pipe(f);
	if (llp == NULL)
		goto fallback;

	if (llp->size < bufsize) {
		if (llp->can_grow) {
			res = fcntl(llp->pipe[0], F_SETPIPE_SZ, bufsize);
			if (res == -1) {
				llp->can_grow = 0;
				goto fallback;
			}
			llp->size = res;
		}
		if (llp->size < bufsize)
			goto fallback;
	}

	res = splice(tmfs_chan_fd(ch), NULL, llp->pipe[1], NULL, bufsize, 0);
	err = errno;

	if (tmfs_session_exited(se))
		return 0;

	if (res == -1) {
		if (err == ENODEV) {
			tmfs_session_exit(se);
			return 0;
		}
		if (err != EINTR && err != EAGAIN)
			perror("tmfs: splice from device");
		return -err;
	}

	if (res < sizeof(struct tmfs_in_header)) {
		fprintf(stderr, "short splice from tmfs device\n");
		return -EIO;
	}

	tmpbuf = (struct tmfs_buf) {
		.size = res,
		.flags = TMFS_BUF_IS_FD,
		.fd = llp->pipe[0],
	};

	/*
	 * Don't bother with zero copy for small requests.
	 * tmfs_loop_mt() needs to check for FORGET so this more than
	 * just an optimization.
	 */
	if (res < sizeof(struct tmfs_in_header) +
	    sizeof(struct tmfs_write_in) + pagesize) {
		struct tmfs_bufvec src = { .buf[0] = tmpbuf, .count = 1 };
		struct tmfs_bufvec dst = { .buf[0] = *buf, .count = 1 };

		res = tmfs_buf_copy(&dst, &src, 0);
		if (res < 0) {
			fprintf(stderr, "tmfs: copy from pipe: %s\n",
				strerror(-res));
			tmfs_ll_clear_pipe(f);
			return res;
		}
		if (res < tmpbuf.size) {
			fprintf(stderr, "tmfs: copy from pipe: short read\n");
			tmfs_ll_clear_pipe(f);
			return -EIO;
		}
		buf->size = tmpbuf.size;
		return buf->size;
	}

	*buf = tmpbuf;

	return res;

fallback:
	res = tmfs_chan_recv(chp, buf->mem, bufsize);
	if (res <= 0)
		return res;

	buf->size = res;

	return res;
}
#else
static int tmfs_ll_receive_buf(struct tmfs_session *se, struct tmfs_buf *buf,
			       struct tmfs_chan **chp)
{
	(void) se;

	int res = tmfs_chan_recv(chp, buf->mem, buf->size);
	if (res <= 0)
		return res;

	buf->size = res;

	return res;
}
#endif


/*
 * always call tmfs_lowlevel_new_common() internally, to work around a
 * misfeature in the FreeBSD runtime linker, which links the old
 * version of a symbol to internal references.
 */
struct tmfs_session *tmfs_lowlevel_new_common(struct tmfs_args *args,
					      const struct tmfs_lowlevel_ops *op,
					      size_t op_size, void *userdata)
{
	int err;
	struct tmfs_ll *f;
	struct tmfs_session *se;
	struct tmfs_session_ops sop = {
		.process = tmfs_ll_process,
		.destroy = tmfs_ll_destroy,
	};

	if (sizeof(struct tmfs_lowlevel_ops) < op_size) {
		fprintf(stderr, "tmfs: warning: library too old, some operations may not work\n");
		op_size = sizeof(struct tmfs_lowlevel_ops);
	}

	f = (struct tmfs_ll *) calloc(1, sizeof(struct tmfs_ll));
	if (f == NULL) {
		fprintf(stderr, "tmfs: failed to allocate tmfs object\n");
		goto out;
	}

	f->conn.async_read = 1;
	f->conn.max_write = UINT_MAX;
	f->conn.max_readahead = UINT_MAX;
	f->atomic_o_trunc = 0;
	list_init_req(&f->list);
	list_init_req(&f->interrupts);
	list_init_nreq(&f->notify_list);
	f->notify_ctr = 1;
	tmfs_mutex_init(&f->lock);

	err = pthread_key_create(&f->pipe_key, tmfs_ll_pipe_destructor);
	if (err) {
		fprintf(stderr, "tmfs: failed to create thread specific key: %s\n",
			strerror(err));
		goto out_free;
	}

	if (tmfs_opt_parse(args, f, tmfs_ll_opts, tmfs_ll_opt_proc) == -1)
		goto out_key_destroy;

	if (f->debug)
		fprintf(stderr, "TMFS library version: %s\n", PACKAGE_VERSION);

	memcpy(&f->op, op, op_size);
	f->owner = getuid();
	f->userdata = userdata;

	se = tmfs_session_new(&sop, f);
	if (!se)
		goto out_key_destroy;

	se->receive_buf = tmfs_ll_receive_buf;
	se->process_buf = tmfs_ll_process_buf;

	return se;

out_key_destroy:
	pthread_key_delete(f->pipe_key);
out_free:
	pthread_mutex_destroy(&f->lock);
	free(f);
out:
	return NULL;
}


struct tmfs_session *tmfs_lowlevel_new(struct tmfs_args *args,
				       const struct tmfs_lowlevel_ops *op,
				       size_t op_size, void *userdata)
{
	return tmfs_lowlevel_new_common(args, op, op_size, userdata);
}

#ifdef linux
int tmfs_req_getgroups(tmfs_req_t req, int size, gid_t list[])
{
	char *buf;
	size_t bufsize = 1024;
	char path[128];
	int ret;
	int fd;
	unsigned long pid = req->ctx.pid;
	char *s;

	sprintf(path, "/proc/%lu/task/%lu/status", pid, pid);

retry:
	buf = malloc(bufsize);
	if (buf == NULL)
		return -ENOMEM;

	ret = -EIO;
	fd = open(path, O_RDONLY);
	if (fd == -1)
		goto out_free;

	ret = read(fd, buf, bufsize);
	close(fd);
	if (ret == -1) {
		ret = -EIO;
		goto out_free;
	}

	if (ret == bufsize) {
		free(buf);
		bufsize *= 4;
		goto retry;
	}

	ret = -EIO;
	s = strstr(buf, "\nGroups:");
	if (s == NULL)
		goto out_free;

	s += 8;
	ret = 0;
	while (1) {
		char *end;
		unsigned long val = strtoul(s, &end, 0);
		if (end == s)
			break;

		s = end;
		if (ret < size)
			list[ret] = val;
		ret++;
	}

out_free:
	free(buf);
	return ret;
}
#else /* linux */
/*
 * This is currently not implemented on other than Linux...
 */
int tmfs_req_getgroups(tmfs_req_t req, int size, gid_t list[])
{
	return -ENOSYS;
}
#endif

#if !defined(__FreeBSD__) && !defined(__NetBSD__)

static void fill_open_compat(struct tmfs_open_out *arg,
			     const struct tmfs_file_info_compat *f)
{
	arg->fh = f->fh;
	if (f->direct_io)
		arg->open_flags |= FOPEN_DIRECT_IO;
	if (f->keep_cache)
		arg->open_flags |= FOPEN_KEEP_CACHE;
}

static void convert_statfs_compat(const struct statfs *compatbuf,
				  struct statvfs *buf)
{
	buf->f_bsize	= compatbuf->f_bsize;
	buf->f_blocks	= compatbuf->f_blocks;
	buf->f_bfree	= compatbuf->f_bfree;
	buf->f_bavail	= compatbuf->f_bavail;
	buf->f_files	= compatbuf->f_files;
	buf->f_ffree	= compatbuf->f_ffree;
	buf->f_namemax	= compatbuf->f_namelen;
}

int tmfs_reply_open_compat(tmfs_req_t req,
			   const struct tmfs_file_info_compat *f)
{
	struct tmfs_open_out arg;

	memset(&arg, 0, sizeof(arg));
	fill_open_compat(&arg, f);
	return send_reply_ok(req, &arg, sizeof(arg));
}

int tmfs_reply_statfs_compat(tmfs_req_t req, const struct statfs *stbuf)
{
	struct statvfs newbuf;

	memset(&newbuf, 0, sizeof(newbuf));
	convert_statfs_compat(stbuf, &newbuf);

	return tmfs_reply_statfs(req, &newbuf);
}

struct tmfs_session *tmfs_lowlevel_new_compat(const char *opts,
				const struct tmfs_lowlevel_ops_compat *op,
				size_t op_size, void *userdata)
{
	struct tmfs_session *se;
	struct tmfs_args args = TMFS_ARGS_INIT(0, NULL);

	if (opts &&
	    (tmfs_opt_add_arg(&args, "") == -1 ||
	     tmfs_opt_add_arg(&args, "-o") == -1 ||
	     tmfs_opt_add_arg(&args, opts) == -1)) {
		tmfs_opt_free_args(&args);
		return NULL;
	}
	se = tmfs_lowlevel_new(&args, (const struct tmfs_lowlevel_ops *) op,
			       op_size, userdata);
	tmfs_opt_free_args(&args);

	return se;
}

struct tmfs_ll_compat_conf {
	unsigned max_read;
	int set_max_read;
};

static const struct tmfs_opt tmfs_ll_opts_compat[] = {
	{ "max_read=", offsetof(struct tmfs_ll_compat_conf, set_max_read), 1 },
	{ "max_read=%u", offsetof(struct tmfs_ll_compat_conf, max_read), 0 },
	TMFS_OPT_KEY("max_read=", TMFS_OPT_KEY_KEEP),
	TMFS_OPT_END
};

int tmfs_sync_compat_args(struct tmfs_args *args)
{
	struct tmfs_ll_compat_conf conf;

	memset(&conf, 0, sizeof(conf));
	if (tmfs_opt_parse(args, &conf, tmfs_ll_opts_compat, NULL) == -1)
		return -1;

	if (tmfs_opt_insert_arg(args, 1, "-osync_read"))
		return -1;

	if (conf.set_max_read) {
		char tmpbuf[64];

		sprintf(tmpbuf, "-omax_readahead=%u", conf.max_read);
		if (tmfs_opt_insert_arg(args, 1, tmpbuf) == -1)
			return -1;
	}
	return 0;
}

TMFS_SYMVER(".symver tmfs_reply_statfs_compat,tmfs_reply_statfs@TMFS_2.4");
TMFS_SYMVER(".symver tmfs_reply_open_compat,tmfs_reply_open@TMFS_2.4");
TMFS_SYMVER(".symver tmfs_lowlevel_new_compat,tmfs_lowlevel_new@TMFS_2.4");

#else /* __FreeBSD__ || __NetBSD__ */

int tmfs_sync_compat_args(struct tmfs_args *args)
{
	(void) args;
	return 0;
}

#endif /* __FreeBSD__ || __NetBSD__ */

struct tmfs_session *tmfs_lowlevel_new_compat25(struct tmfs_args *args,
				const struct tmfs_lowlevel_ops_compat25 *op,
				size_t op_size, void *userdata)
{
	if (tmfs_sync_compat_args(args) == -1)
		return NULL;

	return tmfs_lowlevel_new_common(args,
					(const struct tmfs_lowlevel_ops *) op,
					op_size, userdata);
}

TMFS_SYMVER(".symver tmfs_lowlevel_new_compat25,tmfs_lowlevel_new@TMFS_2.5");
