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
#define IOCTL_FLAGS 1
#define OPEN_FLAGS 2

struct log_bit
{
    log_bit() {
#define _ADD(g, d) add(g, d, #d)

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
        _ADD(IOCTL_FLAGS, FUSE_IOCTL_COMPAT);
        _ADD(IOCTL_FLAGS, FUSE_IOCTL_UNRESTRICTED);
        _ADD(IOCTL_FLAGS, FUSE_IOCTL_RETRY);
        _ADD(IOCTL_FLAGS, FUSE_IOCTL_DIR);

        _ADD(OPEN_FLAGS, O_ACCMODE);
        _ADD(OPEN_FLAGS, O_RDONLY);
        _ADD(OPEN_FLAGS, O_WRONLY);
        _ADD(OPEN_FLAGS, O_RDWR);
        _ADD(OPEN_FLAGS, O_CREAT);
        _ADD(OPEN_FLAGS, O_EXCL);
        _ADD(OPEN_FLAGS, O_NOCTTY);
        _ADD(OPEN_FLAGS, O_TRUNC);
        _ADD(OPEN_FLAGS, O_APPEND);
        _ADD(OPEN_FLAGS, O_NONBLOCK);
        _ADD(OPEN_FLAGS, O_SYNC);
        _ADD(OPEN_FLAGS, O_ASYNC);
        add(OPEN_FLAGS, 32768, "__O_LARGEFILE");
        _ADD(OPEN_FLAGS, __O_DIRECTORY);
        _ADD(OPEN_FLAGS, __O_NOFOLLOW);
        _ADD(OPEN_FLAGS, __O_CLOEXEC);
        _ADD(OPEN_FLAGS, __O_DIRECT);
        _ADD(OPEN_FLAGS, __O_NOATIME);
        _ADD(OPEN_FLAGS, __O_PATH);
        _ADD(OPEN_FLAGS, __O_DSYNC);
        _ADD(OPEN_FLAGS, __O_TMPFILE);
#undef _ADD
    }

    void add(int group, uint64_t value, const char* def) {
        if (!value) return ;

        if (maps_.size() <= group)
            maps_.resize(group + 1);
        auto & m = maps_[group];
        m[value] = def;
    }

    std::string get(int group, uint64_t value) {
        if (!value)
            return "0";

        if (maps_.size() <= group)
            return "nil-group";

        std::string s;
        auto & m = maps_[group];
        for (auto & kv : m)
        {
            std::string flag;
            if ((value & kv.first) == kv.first) {
                flag = kv.second;
                value -= kv.first;
                s += flag;
                s += "|";
            }
        }

        if (value) {
            s += std::to_string((unsigned long long)value);
            s += "|";
        }

        if (!s.empty()) {
            s = s.substr(0, s.size() - 1);
        }

        return s;
    }

    std::deque<std::map<uint64_t, std::string>> maps_;
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
        sprintf(buf, "flags:%d, ", fi->flags);
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
