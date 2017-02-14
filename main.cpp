#include <fuse3/fuse_lowlevel.h>
#include <fuse3/fuse.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <stddef.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <map>
#include <string>
#include <string.h>
#include <stdarg.h>
#include <stdint.h>
#include <boost/algorithm/string.hpp>
#include <dirent.h>
#include <time.h>
#include <deque>
#include <memory>

void log(const char* fmt, ...)
{
    static const int buflen = 64 * 1024;
    static char *buf = new char[buflen];
    va_list args;
    va_start(args, fmt);
    int len = vsnprintf(buf, buflen - 1, fmt, args);
    va_end(args);

    static FILE * f = NULL;
    if (!f) {
        f = fopen("/home/yyz/test/log", "a+");
    }
    fwrite(buf, 1, len, f);
    fwrite("\n", 1, 1, f);
    fflush(f);
}

#define F_LCK       0
#define F_CTL       1
#define F_SEEK      2

struct log_str
{
    log_str() {
#define _ADD(g, d) add(g, d, #d)
        _ADD(F_LCK, F_RDLCK);
        _ADD(F_LCK, F_WRLCK);
        _ADD(F_LCK, F_UNLCK);

        _ADD(F_CTL, F_GETLK);
        _ADD(F_CTL, F_SETLK);
        _ADD(F_CTL, F_SETLKW);
#undef _ADD
    }

    void add(int group, int value, const char* def) {
        if (maps_.size() <= group)
            maps_.resize(group + 1);
        auto & l = maps_[group];
        if (l.size() <= value)
            l.resize(value + 1);
        l[value] = def;
    }

    const char* get(int group, int value) {
        if (maps_.size() <= group)
            return "nil-group";
        auto & l = maps_[group];
        if (l.size() <= value)
            return "nil-value";

        return l[value].c_str();
    }

    std::deque<std::deque<std::string>> maps_;
};
log_str g_logstr;
#define LOGSTR(g, v) g_logstr.get(g, v)

#define B_FI 0
#define B_FIOCTL 1

struct log_bit
{
    log_bit() {
#define _ADD(g, d)                                          \
    do {                                                    \
      if (!add(g, d, #d)) {                                 \
          log("Add log_bit error. %s=%d", #d, d);           \
      }                                                     \
    } while(0)

        _ADD(B_FI, FUSE_CAP_ASYNC_READ);
        _ADD(B_FI, FUSE_CAP_POSIX_LOCKS);
        _ADD(B_FI, FUSE_CAP_ATOMIC_O_TRUNC);
        _ADD(B_FI, FUSE_CAP_EXPORT_SUPPORT);
        _ADD(B_FI, FUSE_CAP_DONT_MASK);
        _ADD(B_FI, FUSE_CAP_SPLICE_WRITE);
        _ADD(B_FI, FUSE_CAP_SPLICE_MOVE);
        _ADD(B_FI, FUSE_CAP_SPLICE_READ);
        _ADD(B_FI, FUSE_CAP_FLOCK_LOCKS);
        _ADD(B_FI, FUSE_CAP_IOCTL_DIR);
        _ADD(B_FI, FUSE_CAP_AUTO_INVAL_DATA);
        _ADD(B_FI, FUSE_CAP_READDIRPLUS);
        _ADD(B_FI, FUSE_CAP_READDIRPLUS_AUTO);
        _ADD(B_FI, FUSE_CAP_ASYNC_DIO);
        _ADD(B_FI, FUSE_CAP_WRITEBACK_CACHE);
        _ADD(B_FI, FUSE_CAP_NO_OPEN_SUPPORT);
        _ADD(B_FI, FUSE_CAP_PARALLEL_DIROPS);
        _ADD(B_FI, FUSE_CAP_POSIX_ACL);
        _ADD(B_FI, FUSE_CAP_HANDLE_KILLPRIV);
        _ADD(B_FIOCTL, FUSE_IOCTL_COMPAT);
        _ADD(B_FIOCTL, FUSE_IOCTL_UNRESTRICTED);
        _ADD(B_FIOCTL, FUSE_IOCTL_RETRY);
        _ADD(B_FIOCTL, FUSE_IOCTL_DIR);
#undef _ADD
    }

    bool add(int group, uint64_t value, const char* def) {
        if (!value) return false;

        int bit = 0;
        for (int i = 0; i < 64; ++i, ++bit) {
            if (value == 1)
                break;

            if (value & 0x1)
                return false;

            value = value >> 1;
        }

        if (maps_.size() <= group)
            maps_.resize(group + 1);
        auto & l = maps_[group];
        if (l.size() <= bit)
            l.resize(bit + 1);
        l[bit] = def;
        return true;
    }

    std::string get(int group, uint64_t value) {
        if (!value)
            return "0";

        if (maps_.size() <= group)
            return "nil-group";

        std::string s;
        auto & l = maps_[group];
        for (int i = 0; i < 64; ++i)
        {
            std::string flag;
            if (value & ((uint64_t)1 << i)) {
                if (l.size() <= i)
                    flag = "nil-value";
                else
                    flag = l[i];

                s += flag;
                s += "|";
            }
        }
        if (!s.empty()) {
            s = s.substr(0, s.size() - 1);
        }

        return s;
    }

    std::deque<std::deque<std::string>> maps_;
};
log_bit g_logbit;
#define LOGBIT(g, v) g_logbit.get(g, v).c_str()

std::string time2string(const struct timespec tv)
{
    char c[64] = {};
    struct tm *ptm = gmtime(&tv.tv_sec);
    strftime(c, sizeof(c), "%F %T", ptm);
    return c;
}

#define LOGTIME(tv) time2string(tv).c_str()

std::string stat2string(struct stat *st)
{
    char buf[1024];
    sprintf(buf, "dev:%ld, mode:0%o, size:%lu, uid:%d, gid:%d, atime:%s, mtime:%s, ctime:%s",
            st->st_dev, st->st_mode, (unsigned long)st->st_size, st->st_uid, st->st_gid,
            LOGTIME(st->st_atim), LOGTIME(st->st_mtim), LOGTIME(st->st_ctim));
    return buf;
}

std::string fi2string(struct fuse_file_info *fi)
{
    if (!fi) return "NULL";

    std::string s;
    char buf[1024];
    if (fi->flags) {
        sprintf(buf, "flags:%s, ", LOGBIT(B_FI, fi->flags));
        s += buf;
    }

#define _FI_FIELD(f, name, charset) \
    do { \
        if (f) { \
            sprintf(buf, name ":%" charset ", ", f); \
            s += buf; \
        } \
    } while(0)

#define _FI_FIELD_D(f, name) _FI_FIELD(f, name, "d")

    _FI_FIELD_D(fi->writepage, "writepage");
    _FI_FIELD_D(fi->direct_io, "direct_io");
    _FI_FIELD_D(fi->keep_cache, "keep_cache");
    _FI_FIELD_D(fi->flush, "flush");
    _FI_FIELD_D(fi->nonseekable, "nonseekable");
    _FI_FIELD_D(fi->flock_release, "flock_release");
    _FI_FIELD(fi->fh, "fh", "lu");
    _FI_FIELD(fi->lock_owner, "lock_owner", "lu");
    _FI_FIELD(fi->poll_events, "poll_events", "u");

#undef _FI_FIELD_D
#undef _FI_FIELD

    //sprintf(buf, "flags:%d:%s, writepage:%d, direct_io:%d, keep_cache:%d, flush:%d, "
            //"nonseekable:%d, flock_release:%d, fh:%lu, lock_owner:%lu, poll_events:%u",
            //fi->flags, LOGBIT(B_FI, fi->flags), fi->writepage, fi->direct_io, fi->keep_cache,
            //fi->flush, fi->nonseekable, fi->flock_release, fi->fh, fi->lock_owner, fi->poll_events);
    return s;
}
#define LOGFI(fi) fi2string(fi).c_str()

struct INode : stat
{
    INode() {
        memset(static_cast<stat*>(this), 0, sizeof(struct stat));
        st_ino = ++s_ino_incrementer;
        st_nlink = 1;
        init_flock();
        init_times();
        xattrs_.clear();
    }

    void init_flock() {
        flock_.l_type = F_UNLCK;
        flock_.l_whence = SEEK_SET;
        flock_.l_start = flock_.l_len = 0;
        flock_.l_pid = 0;
    }

    void init_times() {
        struct timespec ts;
        clock_gettime(CLOCK_REALTIME, &ts);
        st_atim = ts;
        st_ctim = ts;
        st_mtim = ts;
    }

    void on_access() {
        struct timespec ts;
        clock_gettime(CLOCK_REALTIME, &ts);
        st_atim = ts;
    }

    void on_modify() {
        struct timespec ts;
        clock_gettime(CLOCK_REALTIME, &ts);
        st_mtim = ts;
    }

    void on_change() {
        struct timespec ts;
        clock_gettime(CLOCK_REALTIME, &ts);
        st_ctim = ts;
    }

    int write_buf(const struct fuse_bufvec *buf, off_t off) {
        size_t len = fuse_buf_size(buf);
        log("%s(off=%lu, len=%lu)", __func__, off, len);

        size_t tail = len + off;
        if (file_content_.size() < tail)
            file_content_.resize(tail);

        for (size_t i = 0; i < buf->count; ++i) {
            memcpy(&file_content_[off], buf->buf[i].mem, buf->buf[i].size);
            off += buf->buf[i].size;
        }

        return len;
    }

    int read_buf(struct fuse_bufvec **bufp, size_t size, off_t off) {
        size_t len = 0;
        *bufp = (struct fuse_bufvec *)malloc(sizeof(struct fuse_bufvec));
        struct fuse_bufvec *buf = *bufp;
        *buf = FUSE_BUFVEC_INIT(size);
        for (size_t i = 0; i < buf->count; ++i) {
            size_t file_remain = file_content_.size() - off;
            if (buf->buf[i].size < file_remain) {
                buf->buf[i].mem = (char*)malloc(buf->buf[i].size);
                memcpy(buf->buf[i].mem, &file_content_[off], buf->buf[i].size);
                off += buf->buf[i].size;
                len += buf->buf[i].size;
            } else {
                buf->buf[i].mem = (char*)malloc(file_remain);
                memcpy(buf->buf[i].mem, &file_content_[off], file_remain);
                len += file_remain;
                break;
            }
        }

        log("%s(off=%lu, expect_size=%lu, len=%lu)", __func__, off, size, len);
        return len;
    }

    flock flock_;
    std::map<std::string, std::string> xattrs_;

    // 文件内容
    std::string file_content_;

    static ino_t s_ino_incrementer;
};
ino_t INode::s_ino_incrementer = 0;
typedef std::shared_ptr<INode> INodePtr;

struct Cache
{
    std::map<std::string, INodePtr> inodes;

    void InitRoot()
    {
        CreateINode("/", 040777, 0);
    }

    bool Exists(const char* path)
    {
        return !!inodes.count(path);
    }

    INodePtr GetINode(const char* path)
    {
        auto it = inodes.find(path);
        if (it == inodes.end()) return INodePtr();
        return it->second;
    }

    bool DeleteINode(const char* path)
    {
        return !!inodes.erase(path);
    }

    int CreateINode(const char* path, mode_t m, dev_t dev)
    {
        if (Exists(path)) return -EEXIST;
        auto & inode = inodes[path];
        inode.reset(new INode);
        inode->st_mode = m;
        inode->st_size = 0;
        inode->st_dev = dev;
        inode->st_uid = getuid();
        inode->st_gid = getgid();
        return 0;
    }

    int Chmod(const char* path, mode_t m)
    {
        if (!Exists(path)) return -EEXIST;
        auto & inode = inodes[path];
        inode->st_mode &= ~(mode_t)00000;
        inode->st_mode |= m;
        inode->on_change();
        return 0;
    }

    int Rename(const char *path, const char *new_path, unsigned int flags)
    {
        (void)flags;
        if (!Exists(path)) return -EEXIST;
        if (Exists(new_path)) return -EEXIST;
        inodes[new_path] = inodes[path];
        inodes.erase(path);
        inodes[new_path]->on_change();
        return 0;
    }

    std::map<std::string, struct stat> LsDir(const char* path)
    {
        std::map<std::string, struct stat> results;

        std::string spath = path;
        if (spath.length() <= 0) return results;
        if (spath[spath.length() - 1] != '/')
            spath += '/';

        for (auto & kv : inodes)
        {
            if (!boost::starts_with(kv.first, spath))
                continue;

            if (kv.first == spath)
                continue;

            std::string sub_path = kv.first.substr(spath.length(), -1);
            if (sub_path.find('/') != std::string::npos)
                continue;

            results[sub_path] = *kv.second;
        }

        return results;
    }
};
Cache g_cache;

/**
 * Initialize filesystem
 *
 * The return value will passed in the private_data field of
 * fuse_context to all file operations and as a parameter to the
 * destroy() method.
 */
void* mzfs_init(struct fuse_conn_info *conn, struct fuse_config *cfg)
{
    log(__func__);
    g_cache.InitRoot();
    return NULL;
}

/**
 * Clean up filesystem
 *
 * Called on filesystem exit.
 */
void mzfs_destroy(void *)
{
    log(__func__);
}

/** Get file attributes.
 *
 * Similar to stat().  The 'st_dev' and 'st_blksize' fields are
 * ignored. The 'st_ino' field is ignored except if the 'use_ino'
 * mount option is given.
 *
 * `fi` will always be NULL if the file is not currenly open, but
 * may also be NULL if the file is open.
 */
int mzfs_getattr(const char *path, struct stat *stbuf, struct fuse_file_info *fi)
{
    log("%s(%s)", __func__, path);
    auto it = g_cache.inodes.find(path);
    if (it == g_cache.inodes.end()) {
        memset(stbuf, 0, sizeof(struct stat));
        return -ENOENT;
    }

    INodePtr inode = it->second;
    if (!inode->file_content_.empty())
        inode->st_size = inode->file_content_.size();

    *stbuf = *inode;
    log("attr {%s}", stat2string(stbuf).c_str());
	return 0;
}

/** Read the target of a symbolic link
 *
 * The buffer should be filled with a null terminated string.  The
 * buffer size argument includes the space for the terminating
 * null character.	If the linkname is too long to fit in the
 * buffer, it should be truncated.	The return value should be 0
 * for success.
 */
int mzfs_readlink(const char *path, char *, size_t)
{
    log("%s(%s)", __func__, path);
    return -1;
}

/** Create a file node
 *
 * This is called for creation of all non-directory, non-symlink
 * nodes.  If the filesystem defines a create() method, then for
 * regular files that will be called instead.
 */
int mzfs_mknod(const char *path, mode_t m, dev_t dev)
{
    log("%s(path=\"%s\", mode=0%o, dev=%d)", __func__, path, m, dev);
    return g_cache.CreateINode(path, m, dev);
}

/** Create a directory
 *
 * Note that the mode argument may not have the type specification
 * bits set, i.e. S_ISDIR(mode) can be false.  To obtain the
 * correct directory type bits use  mode|S_IFDIR
 * */
int mzfs_mkdir(const char *path, mode_t m)
{
    log("%s(path=\"%s\", mode=0%o)", __func__, path, m);
    return g_cache.CreateINode(path, m | 040000, 0);
}

/** Remove a file */
int mzfs_unlink(const char *path)
{
    log("%s(%s)", __func__, path);
    INodePtr inode = g_cache.GetINode(path);
    if (!inode)
        return -ENOENT;

    if (S_ISDIR(inode->st_mode))
        return -EISDIR;

    if (!g_cache.DeleteINode(path))
        return -ENOENT;

    return 0;
}

/** Remove a directory */
int mzfs_rmdir(const char *path)
{
    log("%s(%s)", __func__, path);
    INodePtr inode = g_cache.GetINode(path);
    if (!inode)
        return -ENOENT;

    if (!S_ISDIR(inode->st_mode))
        return -ENOTDIR;

    if (!g_cache.DeleteINode(path))
        return -ENOENT;

    return 0;
}

/** Create a symbolic link */
int mzfs_symlink(const char *path, const char *ln_path)
{
    log("%s(%s, %s)", __func__, path, ln_path);
    return 0;
}

/** Rename a file */
int mzfs_rename(const char *path, const char *new_path, unsigned int flags)
{
    log("%s(%s)", __func__, path);
    return g_cache.Rename(path, new_path, flags);
}

/** Create a hard link to a file */
int mzfs_link(const char *path, const char *ln_path)
{
    log("%s(%s)", __func__, path);
    return 0;
}

/** Change the permission bits of a file
 *
 * `fi` will always be NULL if the file is not currenly open, but
 * may also be NULL if the file is open.
 */
int mzfs_chmod(const char *path, mode_t m, struct fuse_file_info *fi)
{
    log("%s(%s)", __func__, path);
    return g_cache.Chmod(path, m);
}

/** Change the owner and group of a file
 *
 * `fi` will always be NULL if the file is not currenly open, but
 * may also be NULL if the file is open.
 *
 * Unless FUSE_CAP_HANDLE_KILLPRIV is disabled, this method is
 * expected to reset the setuid and setgid bits.
 */
int mzfs_chown(const char *path, uid_t uid, gid_t gid, struct fuse_file_info *fi)
{
    log("%s(%s)", __func__, path);
    return 0;
}

/** Change the size of a file
 *
 * `fi` will always be NULL if the file is not currenly open, but
 * may also be NULL if the file is open.
 *
 * Unless FUSE_CAP_HANDLE_KILLPRIV is disabled, this method is
 * expected to reset the setuid and setgid bits.
 */
int mzfs_truncate(const char *path, off_t offset, struct fuse_file_info *fi)
{
    log("%s(path=\"%s\", fi:{%s})", __func__, path, LOGFI(fi));
    return 0;
}

/** File open operation
 *
 * No creation (O_CREAT, O_EXCL) and by default also no
 * truncation (O_TRUNC) flags will be passed to open(). If an
 * application specifies O_TRUNC, fuse first calls truncate()
 * and then open(). Only if 'atomic_o_trunc' has been
 * specified and kernel version is 2.6.24 or later, O_TRUNC is
 * passed on to open.
 *
 * Unless the 'default_permissions' mount option is given,
 * open should check if the operation is permitted for the
 * given flags. Optionally open may also return an arbitrary
 * filehandle in the fuse_file_info structure, which will be
 * passed to all file operations.
 */
int mzfs_open(const char *path, struct fuse_file_info *fi)
{
    log("%s(path=\"%s\", fi:{%s})", __func__, path, LOGFI(fi));
    INodePtr inode = g_cache.GetINode(path);
    if (!inode)
        return -ENOENT;

    if (fi->flags & FUSE_CAP_SPLICE_READ) {
        std::string s;
        inode->file_content_.swap(s);
        inode->st_size = 0;
    }
    return 0;
}

/** Read data from an open file
 *
 * Read should return exactly the number of bytes requested except
 * on EOF or error, otherwise the rest of the data will be
 * substituted with zeroes.	 An exception to this is when the
 * 'direct_io' mount option is specified, in which case the return
 * value of the read system call will reflect the return value of
 * this operation.
 */
int mzfs_read(const char *path, char * buf, size_t len, off_t offset,
        struct fuse_file_info *)
{
    log("%s(%s)", __func__, path);
    return -ENOENT;
}

/** Write data to an open file
 *
 * Write should return exactly the number of bytes requested
 * except on error.	 An exception to this is when the 'direct_io'
 * mount option is specified (see read operation).
 *
 * Unless FUSE_CAP_HANDLE_KILLPRIV is disabled, this method is
 * expected to reset the setuid and setgid bits.
 */
int mzfs_write(const char *path, const char * buf, size_t len, off_t offset,
          struct fuse_file_info *)
{
    log("%s(%s)", __func__, path);
    return -ENOENT;
}

/** Get file system statistics
 *
 * The 'f_favail', 'f_fsid' and 'f_flag' fields are ignored
 */
int mzfs_statfs(const char *path, struct statvfs * st)
{
    log("%s(%s)", __func__, path);
    memset(st, 0, sizeof(*st));
    return -ENOENT;
}

/** Possibly flush cached data
 *
 * BIG NOTE: This is not equivalent to fsync().  It's not a
 * request to sync dirty data.
 *
 * Flush is called on each close() of a file descriptor.  So if a
 * filesystem wants to return write errors in close() and the file
 * has cached dirty data, this is a good place to write back data
 * and return any errors.  Since many applications ignore close()
 * errors this is not always useful.
 *
 * NOTE: The flush() method may be called more than once for each
 * open().	This happens if more than one file descriptor refers
 * to an opened file due to dup(), dup2() or fork() calls.	It is
 * not possible to determine if a flush is final, so each flush
 * should be treated equally.  Multiple write-flush sequences are
 * relatively rare, so this shouldn't be a problem.
 *
 * Filesystems shouldn't assume that flush will always be called
 * after some writes, or that if will be called at all.
 */
int mzfs_flush(const char *path, struct fuse_file_info *fi)
{
    log("%s(path=\"%s\", fi:{%s})", __func__, path, LOGFI(fi));
    return 0;
}

/** Release an open file
 *
 * Release is called when there are no more references to an open
 * file: all file descriptors are closed and all memory mappings
 * are unmapped.
 *
 * For every open() call there will be exactly one release() call
 * with the same flags and file descriptor.	 It is possible to
 * have a file opened more than once, in which case only the last
 * release will mean, that no more reads/writes will happen on the
 * file.  The return value of release is ignored.
 */
int mzfs_release(const char *path, struct fuse_file_info *fi)
{
    log("%s(path=\"%s\", fi:{%s})", __func__, path, LOGFI(fi));
    return 0;
}

/** Synchronize file contents
 *
 * If the datasync parameter is non-zero, then only the user data
 * should be flushed, not the meta data.
 */
int mzfs_fsync(const char *path, int , struct fuse_file_info *fi)
{
    log("%s(path=\"%s\", fi:{%s})", __func__, path, LOGFI(fi));
    return 0;
}

/** Set extended attributes */
int mzfs_setxattr(const char *path, const char *name, const char *value, size_t size, int flags)
{
    log("%s(path=\"%s\", name=\"%s\", value=\"%12s\", size=%lu, flags=%d)",
            __func__, path, name, value, size, flags);
    INodePtr inode = g_cache.GetINode(path);
    if (!inode)
        return -ENOENT;

    inode->xattrs_[name] = std::string(value, size);
    return 0;
}

/** Get extended attributes */
int mzfs_getxattr(const char *path, const char *name, char *value, size_t size)
{
    log("%s(path=\"%s\", name=\"%s\", value=\"%12s\", size=%lu)",
            __func__, path, name, value, size);
    INodePtr inode = g_cache.GetINode(path);
    if (!inode)
        return -ENOENT;

    std::string xattr;
    if (inode->xattrs_.count(name))
        xattr = inode->xattrs_[name];

    size_t len = std::min<size_t>(size, xattr.length());
    memcpy(value, xattr.c_str(), len);
    return len;
}

/** List extended attributes */
int mzfs_listxattr(const char *path, char *buf, size_t len)
{
    log("%s(%s)", __func__, path);
    return 0;
}

/** Remove extended attributes */
int mzfs_removexattr(const char *path, const char *name)
{
    log("%s(path=\"%s\", name=\"%s\")", __func__, path, name);
    INodePtr inode = g_cache.GetINode(path);
    if (!inode)
        return -ENOENT;

    inode->xattrs_.erase(name);
    return 0;
}

/** Open directory
 *
 * Unless the 'default_permissions' mount option is given,
 * this method should check if opendir is permitted for this
 * directory. Optionally opendir may also return an arbitrary
 * filehandle in the fuse_file_info structure, which will be
 * passed to readdir, closedir and fsyncdir.
 */
int mzfs_opendir(const char *path, struct fuse_file_info *fi)
{
    log("%s(%s)", __func__, path);
    INodePtr d = g_cache.GetINode(path);
    if (!d) {
        return -ENOENT;
    }

    if (!S_ISDIR(d->st_mode)) {
        return -ENOTDIR;
    }

    fi->fh = (uint64_t)d.get();
    fi->fh = (uint64_t)(malloc(sizeof(uintptr_t)));
    log("returns fi->fh = %lu, fi->flags = 0%o", fi->fh, fi->flags);
    return 0;
}

/** Release directory
 */
int mzfs_releasedir(const char *path, struct fuse_file_info *fi)
{
    log("%s(%s, fi->fh = %lu)", __func__, path, fi->fh);
    fi->fh = 0;
    return 0;
}

/** Read directory
 *
 * The filesystem may choose between two modes of operation:
 *
 * 1) The readdir implementation ignores the offset parameter, and
 * passes zero to the filler function's offset.  The filler
 * function will not return '1' (unless an error happens), so the
 * whole directory is read in a single readdir operation.
 *
 * 2) The readdir implementation keeps track of the offsets of the
 * directory entries.  It uses the offset parameter and always
 * passes non-zero offset to the filler function.  When the buffer
 * is full (or an error happens) the filler function will return
 * '1'.
 */
void do_filler(fuse_fill_dir_t filler, void *buf, const char *name,
        const struct stat *stbuf, off_t off,
        enum fuse_fill_dir_flags flags)
{
    log("%s(name=\"%s\", stbuf=%p, off=%d, flags=%d)", __func__, name, stbuf, off, flags);
    filler(buf, name, stbuf, off, flags);
}

int mzfs_readdir(const char *path, void *buf, fuse_fill_dir_t filler, off_t offset,
        struct fuse_file_info *, enum fuse_readdir_flags flags)
{
    log("%s(%s)", __func__, path);
    INodePtr inode = g_cache.GetINode(path);
    if (!inode) return -ENOENT;

    if (!S_ISDIR(inode->st_mode)) {
        do_filler(filler, buf, path, NULL, 0, (fuse_fill_dir_flags)0);
    } else {
        //filler(buf, ".", static_cast<struct stat*>(inode), 0, (fuse_fill_dir_flags)0);
        do_filler(filler, buf, ".", static_cast<struct stat*>(inode.get()), 0, FUSE_FILL_DIR_PLUS);
        do_filler(filler, buf, "..", NULL, 0, FUSE_FILL_DIR_PLUS);
        std::map<std::string, struct stat> m = g_cache.LsDir(path);
        for (auto &kv : m)
        {
            do_filler(filler, buf, kv.first.c_str(), &kv.second, 0, FUSE_FILL_DIR_PLUS);
        }
    }
    return 0;
}

/** Synchronize directory contents
 *
 * If the datasync parameter is non-zero, then only the user data
 * should be flushed, not the meta data
 */
int mzfs_fsyncdir(const char *path, int, struct fuse_file_info *)
{
    log("%s(%s)", __func__, path);
    return 0;
}

/**
 * Check file access permissions
 *
 * This will be called for the access() system call.  If the
 * 'default_permissions' mount option is given, this method is not
 * called.
 *
 * This method is not called under Linux kernel versions 2.4.x
 */
int mzfs_access(const char *path, int)
{
    log("%s(%s)", __func__, path);
    return 0;
}

/**
 * Create and open a file
 *
 * If the file does not exist, first create it with the specified
 * mode, and then open it.
 *
 * If this method is not implemented or under Linux kernel
 * versions earlier than 2.6.15, the mknod() and open() methods
 * will be called instead.
 */
//int mzfs_create(const char *path, mode_t m, struct fuse_file_info *)
//{
    //log(__func__);
    //if (g_cache.files.count(path)) {
        //return 0;
    //}
//
    //g_cache.files[path] = m;
    //return 0;
//}

/**
 * Perform POSIX file locking operation
 *
 * The cmd argument will be either F_GETLK, F_SETLK or F_SETLKW.
 *
 * For the meaning of fields in 'struct flock' see the man page
 * for fcntl(2).  The l_whence field will always be set to
 * SEEK_SET.
 *
 * For checking lock ownership, the 'fuse_file_info->owner'
 * argument must be used.
 *
 * For F_GETLK operation, the library will first check currently
 * held locks, and if a conflicting lock is found it will return
 * information without calling this method.	 This ensures, that
 * for local locks the l_pid field is correctly filled in.	The
 * results may not be accurate in case of race conditions and in
 * the presence of hard links, but it's unlikely that an
 * application would rely on accurate GETLK results in these
 * cases.  If a conflicting lock is not found, this method will be
 * called, and the filesystem may fill out l_pid by a meaningful
 * value, or it may leave this field zero.
 *
 * For F_SETLK and F_SETLKW the l_pid field will be set to the pid
 * of the process performing the locking operation.
 *
 * Note: if this method is not implemented, the kernel will still
 * allow file locking to work locally.  Hence it is only
 * interesting for network filesystems and similar.
 */
int mzfs_lock(const char *path, struct fuse_file_info *fi, int cmd, struct flock *fl)
{
    log("%s(path=\"%s\", fi->lock_owner=%lu, cmd=%s, flock.l_type=%s, "
            "flock.l_pid=%u)", __func__, path, fi->lock_owner, LOGSTR(F_CTL, cmd), LOGSTR(F_LCK, fl->l_type), fl->l_pid);
    INodePtr inode = g_cache.GetINode(path);
    if (!inode)
        return -ENOENT;

    switch (cmd) {
        case F_GETLK:
            if (inode->flock_.l_type == F_UNLCK)
                fl->l_type = F_UNLCK;
            else
                *fl = inode->flock_;
            return 0;

        case F_SETLK:
            inode->flock_ = *fl;
            //fi->lock_owner = fl->l_pid;
            return 0;

        case F_SETLKW:
            inode->flock_ = *fl;
            //fi->lock_owner = fl->l_pid;
            return 0;
    }
    return 0;
}

/**
 * Change the access and modification times of a file with
 * nanosecond resolution
 *
 * This supersedes the old utime() interface.  New applications
 * should use this.
 *
 * `fi` will always be NULL if the file is not currenly open, but
 * may also be NULL if the file is open.
 *
 * See the utimensat(2) man page for details.
 */
int mzfs_utimens(const char *path, const struct timespec tv[2],
        struct fuse_file_info *fi)
{
    log("%s(path=\"%s\", atime=\"%s\", mtime=\"%s\")", __func__, path,
            LOGTIME(tv[0]), LOGTIME(tv[1]));

    INodePtr inode = g_cache.GetINode(path);
    if (!inode)
        return -ENOENT;

    inode->on_access();
    inode->on_modify();
    inode->on_change();
    //inode->st_atim = tv[0];
    //inode->st_mtim = tv[1];
    return 0;
}

/**
 * Map block index within file to block index within device
 *
 * Note: This makes sense only for block device backed filesystems
 * mounted with the 'blkdev' option
 */
int mzfs_bmap(const char *path, size_t blocksize, uint64_t *idx)
{
    log("%s(%s)", __func__, path);
    return 0;
}

/**
 * Ioctl
 *
 * flags will have FUSE_IOCTL_COMPAT set for 32bit ioctls in
 * 64bit environment.  The size and direction of data is
 * determined by _IOC_*() decoding of cmd.  For _IOC_NONE,
 * data will be NULL, for _IOC_WRITE data is out area, for
 * _IOC_READ in area and if both are set in/out area.  In all
 * non-NULL cases, the area is of _IOC_SIZE(cmd) bytes.
 *
 * If flags has FUSE_IOCTL_DIR then the fuse_file_info refers to a
 * directory file handle.
 */
int mzfs_ioctl(const char *path, int cmd, void *arg,
          struct fuse_file_info *, unsigned int flags, void *data)
{
    log("%s(%s)", __func__, path);
    return 0;
}

/**
 * Poll for IO readiness events
 *
 * Note: If ph is non-NULL, the client should notify
 * when IO readiness events occur by calling
 * fuse_notify_poll() with the specified ph.
 *
 * Regardless of the number of times poll with a non-NULL ph
 * is received, single notification is enough to clear all.
 * Notifying more times incurs overhead but doesn't harm
 * correctness.
 *
 * The callee is responsible for destroying ph with
 * fuse_pollhandle_destroy() when no longer in use.
 */
int mzfs_poll(const char *path, struct fuse_file_info *,
         struct fuse_pollhandle *ph, unsigned *reventsp)
{
    log("%s(%s)", __func__, path);
    return 0;
}

/** Write contents of buffer to an open file
 *
 * Similar to the write() method, but data is supplied in a
 * generic buffer.  Use fuse_buf_copy() to transfer data to
 * the destination.
 *
 * Unless FUSE_CAP_HANDLE_KILLPRIV is disabled, this method is
 * expected to reset the setuid and setgid bits.
 */
int mzfs_write_buf(const char *path, struct fuse_bufvec *buf, off_t off,
          struct fuse_file_info *fi)
{
    log("%s(path=\"%s\", off=%lu)", __func__, path, off);
    log("fi:{%s}", LOGFI(fi));
    INodePtr inode = g_cache.GetINode(path);
    if (!inode)
        return -ENOENT;

    if (S_ISDIR(inode->st_mode))
        return -EISDIR;

    return inode->write_buf(buf, off);
}

/** Store data from an open file in a buffer
 *
 * Similar to the read() method, but data is stored and
 * returned in a generic buffer.
 *
 * No actual copying of data has to take place, the source
 * file descriptor may simply be stored in the buffer for
 * later data transfer.
 *
 * The buffer must be allocated dynamically and stored at the
 * location pointed to by bufp.  If the buffer contains memory
 * regions, they too must be allocated using malloc().  The
 * allocated memory will be freed by the caller.
 */
int mzfs_read_buf(const char *path, struct fuse_bufvec **bufp,
         size_t size, off_t off, struct fuse_file_info *)
{
    log("%s(path=\"%s\", size=%lu, off=%lu)", __func__, path, size, off);
    INodePtr inode = g_cache.GetINode(path);
    if (!inode)
        return -ENOENT;

    if (S_ISDIR(inode->st_mode))
        return -EISDIR;

    return inode->read_buf(bufp, size, off);
}

/**
 * Perform BSD file locking operation
 *
 * The op argument will be either LOCK_SH, LOCK_EX or LOCK_UN
 *
 * Nonblocking requests will be indicated by ORing LOCK_NB to
 * the above operations
 *
 * For more information see the flock(2) manual page.
 *
 * Additionally fi->owner will be set to a value unique to
 * this open file.  This same value will be supplied to
 * ->release() when the file is released.
 *
 * Note: if this method is not implemented, the kernel will still
 * allow file locking to work locally.  Hence it is only
 * interesting for network filesystems and similar.
 */
int mzfs_flock(const char *path, struct fuse_file_info *, int op)
{
    log("%s(%s)", __func__, path);
    return 0;
}

/**
 * Allocates space for an open file
 *
 * This function ensures that required space is allocated for specified
 * file.  If this function returns success then any subsequent write
 * request to specified range is guaranteed not to fail because of lack
 * of space on the file system media.
 */
int mzfs_fallocate(const char *path, int, off_t, off_t, struct fuse_file_info *)
{
    log("%s(%s)", __func__, path);
    return 0;
}


int main(int argc, char **argv)
{
    log("start");
    struct fuse_operations op = {};
    op.init = mzfs_init;
    op.destroy = mzfs_destroy;
    op.getattr = mzfs_getattr;
    op.readlink = mzfs_readlink;
    op.mknod = mzfs_mknod;
    op.mkdir = mzfs_mkdir;
    op.unlink = mzfs_unlink;
    op.rmdir = mzfs_rmdir;
    op.symlink = mzfs_symlink;
    op.rename = mzfs_rename;
    op.link = mzfs_link;
    op.chmod = mzfs_chmod;
    op.chown = mzfs_chown;
    op.truncate = mzfs_truncate;
    op.open = mzfs_open;
    op.read = mzfs_read;
    op.write = mzfs_write;
    op.statfs = mzfs_statfs;
    op.flush = mzfs_flush;
    op.release = mzfs_release;
    op.fsync = mzfs_fsync;
    op.setxattr = mzfs_setxattr;
    op.getxattr = mzfs_getxattr;
    op.listxattr = mzfs_listxattr;
    op.removexattr = mzfs_removexattr;
    op.opendir = mzfs_opendir;
    op.releasedir = mzfs_releasedir;
    op.readdir = mzfs_readdir;
    op.fsyncdir = op.fsyncdir;
    op.access = mzfs_access;
    op.lock = mzfs_lock;
    op.poll = mzfs_poll;
    op.write_buf = mzfs_write_buf;
    op.read_buf = mzfs_read_buf;
    op.flock = mzfs_flock;
    op.fallocate = mzfs_fallocate;
    op.utimens = mzfs_utimens;
    op.bmap = mzfs_bmap;
    op.ioctl = mzfs_ioctl;
    int ret = fuse_main(argc, argv, &op, NULL);
    if (0 != ret) {
        printf("fuse_main error:%d\n", ret);
        return ret;
    }

    log("fuse_main exit\n");
    return 0;
}

