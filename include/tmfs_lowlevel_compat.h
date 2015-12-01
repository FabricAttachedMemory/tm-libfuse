/*
  TMFS: Filesystem in Userspace
  Copyright (C) 2001-2007  Miklos Szeredi <miklos@szeredi.hu>

  This program can be distributed under the terms of the GNU LGPLv2.
  See the file COPYING.LIB.
*/

/* these definitions provide source compatibility to prior versions.
   Do not include this file directly! */

struct tmfs_lowlevel_ops_compat25 {
	void (*init) (void *userdata);
	void (*destroy) (void *userdata);
	void (*lookup) (tmfs_req_t req, tmfs_ino_t parent, const char *name);
	void (*forget) (tmfs_req_t req, tmfs_ino_t ino, unsigned long nlookup);
	void (*getattr) (tmfs_req_t req, tmfs_ino_t ino,
			 struct tmfs_file_info *fi);
	void (*setattr) (tmfs_req_t req, tmfs_ino_t ino, struct stat *attr,
			 int to_set, struct tmfs_file_info *fi);
	void (*readlink) (tmfs_req_t req, tmfs_ino_t ino);
	void (*mknod) (tmfs_req_t req, tmfs_ino_t parent, const char *name,
		       mode_t mode, dev_t rdev);
	void (*mkdir) (tmfs_req_t req, tmfs_ino_t parent, const char *name,
		       mode_t mode);
	void (*unlink) (tmfs_req_t req, tmfs_ino_t parent, const char *name);
	void (*rmdir) (tmfs_req_t req, tmfs_ino_t parent, const char *name);
	void (*symlink) (tmfs_req_t req, const char *link, tmfs_ino_t parent,
			 const char *name);
	void (*rename) (tmfs_req_t req, tmfs_ino_t parent, const char *name,
			tmfs_ino_t newparent, const char *newname);
	void (*link) (tmfs_req_t req, tmfs_ino_t ino, tmfs_ino_t newparent,
		      const char *newname);
	void (*open) (tmfs_req_t req, tmfs_ino_t ino,
		      struct tmfs_file_info *fi);
	void (*read) (tmfs_req_t req, tmfs_ino_t ino, size_t size, off_t off,
		      struct tmfs_file_info *fi);
	void (*write) (tmfs_req_t req, tmfs_ino_t ino, const char *buf,
		       size_t size, off_t off, struct tmfs_file_info *fi);
	void (*flush) (tmfs_req_t req, tmfs_ino_t ino,
		       struct tmfs_file_info *fi);
	void (*release) (tmfs_req_t req, tmfs_ino_t ino,
			 struct tmfs_file_info *fi);
	void (*fsync) (tmfs_req_t req, tmfs_ino_t ino, int datasync,
		       struct tmfs_file_info *fi);
	void (*opendir) (tmfs_req_t req, tmfs_ino_t ino,
			 struct tmfs_file_info *fi);
	void (*readdir) (tmfs_req_t req, tmfs_ino_t ino, size_t size, off_t off,
			 struct tmfs_file_info *fi);
	void (*releasedir) (tmfs_req_t req, tmfs_ino_t ino,
			    struct tmfs_file_info *fi);
	void (*fsyncdir) (tmfs_req_t req, tmfs_ino_t ino, int datasync,
			  struct tmfs_file_info *fi);
	void (*statfs) (tmfs_req_t req);
	void (*setxattr) (tmfs_req_t req, tmfs_ino_t ino, const char *name,
			  const char *value, size_t size, int flags);
	void (*getxattr) (tmfs_req_t req, tmfs_ino_t ino, const char *name,
			  size_t size);
	void (*listxattr) (tmfs_req_t req, tmfs_ino_t ino, size_t size);
	void (*removexattr) (tmfs_req_t req, tmfs_ino_t ino, const char *name);
	void (*access) (tmfs_req_t req, tmfs_ino_t ino, int mask);
	void (*create) (tmfs_req_t req, tmfs_ino_t parent, const char *name,
			mode_t mode, struct tmfs_file_info *fi);
};

struct tmfs_session *tmfs_lowlevel_new_compat25(struct tmfs_args *args,
				const struct tmfs_lowlevel_ops_compat25 *op,
				size_t op_size, void *userdata);

size_t tmfs_dirent_size(size_t namelen);

char *tmfs_add_dirent(char *buf, const char *name, const struct stat *stbuf,
		      off_t off);

#if !defined(__FreeBSD__) && !defined(__NetBSD__)

#include <sys/statfs.h>

struct tmfs_lowlevel_ops_compat {
	void (*init) (void *userdata);
	void (*destroy) (void *userdata);
	void (*lookup) (tmfs_req_t req, tmfs_ino_t parent, const char *name);
	void (*forget) (tmfs_req_t req, tmfs_ino_t ino, unsigned long nlookup);
	void (*getattr) (tmfs_req_t req, tmfs_ino_t ino,
			 struct tmfs_file_info_compat *fi);
	void (*setattr) (tmfs_req_t req, tmfs_ino_t ino, struct stat *attr,
			 int to_set, struct tmfs_file_info_compat *fi);
	void (*readlink) (tmfs_req_t req, tmfs_ino_t ino);
	void (*mknod) (tmfs_req_t req, tmfs_ino_t parent, const char *name,
		       mode_t mode, dev_t rdev);
	void (*mkdir) (tmfs_req_t req, tmfs_ino_t parent, const char *name,
		       mode_t mode);
	void (*unlink) (tmfs_req_t req, tmfs_ino_t parent, const char *name);
	void (*rmdir) (tmfs_req_t req, tmfs_ino_t parent, const char *name);
	void (*symlink) (tmfs_req_t req, const char *link, tmfs_ino_t parent,
			 const char *name);
	void (*rename) (tmfs_req_t req, tmfs_ino_t parent, const char *name,
			tmfs_ino_t newparent, const char *newname);
	void (*link) (tmfs_req_t req, tmfs_ino_t ino, tmfs_ino_t newparent,
		      const char *newname);
	void (*open) (tmfs_req_t req, tmfs_ino_t ino,
		      struct tmfs_file_info_compat *fi);
	void (*read) (tmfs_req_t req, tmfs_ino_t ino, size_t size, off_t off,
		      struct tmfs_file_info_compat *fi);
	void (*write) (tmfs_req_t req, tmfs_ino_t ino, const char *buf,
		       size_t size, off_t off, struct tmfs_file_info_compat *fi);
	void (*flush) (tmfs_req_t req, tmfs_ino_t ino,
		       struct tmfs_file_info_compat *fi);
	void (*release) (tmfs_req_t req, tmfs_ino_t ino,
			 struct tmfs_file_info_compat *fi);
	void (*fsync) (tmfs_req_t req, tmfs_ino_t ino, int datasync,
		       struct tmfs_file_info_compat *fi);
	void (*opendir) (tmfs_req_t req, tmfs_ino_t ino,
			 struct tmfs_file_info_compat *fi);
	void (*readdir) (tmfs_req_t req, tmfs_ino_t ino, size_t size, off_t off,
			 struct tmfs_file_info_compat *fi);
	void (*releasedir) (tmfs_req_t req, tmfs_ino_t ino,
			    struct tmfs_file_info_compat *fi);
	void (*fsyncdir) (tmfs_req_t req, tmfs_ino_t ino, int datasync,
			  struct tmfs_file_info_compat *fi);
	void (*statfs) (tmfs_req_t req);
	void (*setxattr) (tmfs_req_t req, tmfs_ino_t ino, const char *name,
			  const char *value, size_t size, int flags);
	void (*getxattr) (tmfs_req_t req, tmfs_ino_t ino, const char *name,
			  size_t size);
	void (*listxattr) (tmfs_req_t req, tmfs_ino_t ino, size_t size);
	void (*removexattr) (tmfs_req_t req, tmfs_ino_t ino, const char *name);
	void (*access) (tmfs_req_t req, tmfs_ino_t ino, int mask);
	void (*create) (tmfs_req_t req, tmfs_ino_t parent, const char *name,
			mode_t mode, struct tmfs_file_info_compat *fi);
};

int tmfs_reply_statfs_compat(tmfs_req_t req, const struct statfs *stbuf);

int tmfs_reply_open_compat(tmfs_req_t req,
			   const struct tmfs_file_info_compat *fi);

struct tmfs_session *tmfs_lowlevel_new_compat(const char *opts,
				const struct tmfs_lowlevel_ops_compat *op,
				size_t op_size, void *userdata);

#endif /* __FreeBSD__ || __NetBSD__ */

struct tmfs_chan_ops_compat24 {
	int (*receive)(struct tmfs_chan *ch, char *buf, size_t size);
	int (*send)(struct tmfs_chan *ch, const struct iovec iov[],
		    size_t count);
	void (*destroy)(struct tmfs_chan *ch);
};

struct tmfs_chan *tmfs_chan_new_compat24(struct tmfs_chan_ops_compat24 *op,
					 int fd, size_t bufsize, void *data);

int tmfs_chan_receive(struct tmfs_chan *ch, char *buf, size_t size);
struct tmfs_chan *tmfs_kern_chan_new(int fd);
