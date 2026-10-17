/*

   nsjail - mount namespace routines using the legacy mount(2) API
   -----------------------------------------

   Copyright 2014 Google Inc. All Rights Reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

     http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.

*/

#include "mnt_legacy.h"

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <memory>
#include <string>
#include <vector>

#include "logs.h"
#include "macros.h"
#include "mnt.h"
#include "util.h"

namespace mnt {
namespace legacy {

static bool isDirectory(const char* path) {
	if (!path) {
		return true;
	}
	struct stat st;
	return stat(path, &st) == 0 && S_ISDIR(st.st_mode);
}

static mount_t prepareMountPoint(const nsjail::MountPt& proto) {
	mount_t mpt = {
	    .mpt = &proto,
	    .src = "",
	    .dst = "",
	    .flags = 0,
	    .is_dir = true,
	    .mounted = false,
	    .fd = -1,
	};

	if (!proto.prefix_src_env().empty()) {
		if (const char* env = getenv(proto.prefix_src_env().c_str())) {
			mpt.src = env;
		} else {
			LOG_W("Environment variable not set: %s", QC(proto.prefix_src_env()));
			return mpt;
		}
	}
	mpt.src += proto.src();

	if (!proto.prefix_dst_env().empty()) {
		if (const char* env = getenv(proto.prefix_dst_env().c_str())) {
			mpt.dst = env;
		} else {
			LOG_W("Environment variable not set: %s", QC(proto.prefix_dst_env()));
			return mpt;
		}
	}
	mpt.dst += proto.dst();

	if (!util::isSafeContainmentPath(mpt.dst)) {
		LOG_E("Mount destination escapes containment via '.'/'..'/NUL: %s", QC(mpt.dst));
		/* Keep the unsafe dst so later mount steps fail closed rather than
		 * treating a cleared path as the jail root. */
		return mpt;
	}

	mpt.flags = proto.rw() ? 0 : (uintptr_t)MS_RDONLY;
	if (proto.is_bind()) {
		mpt.flags |= MS_BIND | MS_REC | MS_PRIVATE;
	}
	if (proto.nosuid()) {
		mpt.flags |= MS_NOSUID;
	}
	if (proto.nodev()) {
		mpt.flags |= MS_NODEV;
	}
	if (proto.noexec()) {
		mpt.flags |= MS_NOEXEC;
	}

	if (proto.has_is_dir()) {
		mpt.is_dir = proto.is_dir();
	} else if (!proto.src_content().empty()) {
		mpt.is_dir = false;
	} else if (mpt.src.empty()) {
		mpt.is_dir = true;
	} else if (mpt.flags & MS_BIND) {
		mpt.is_dir = isDirectory(mpt.src.c_str());
	} else {
		mpt.is_dir = true;
	}

	return mpt;
}

static int tryMountRW(mount_t* mpt, const char* src, const char* dst) {
	int res = mount(src, dst, mpt->mpt->fstype().c_str(), mpt->flags & ~MS_RDONLY,
	    mpt->mpt->options().c_str());

	if (res == -1 && errno == EPERM && (mpt->flags & MS_RDONLY)) {
		LOG_W("mount('%s' -> '%s'): RW failed, falling back to RO", src, dst);
		res = mount(
		    src, dst, mpt->mpt->fstype().c_str(), mpt->flags, mpt->mpt->options().c_str());
	}
	return res;
}

static bool createMountTarget(const std::string& path, bool is_dir) {
	if (is_dir) {
		if (mkdir(path.c_str(), 0711) == -1 && errno != EEXIST) {
			if (errno != EROFS || !util::existsAsDir(path.c_str())) {
				PLOG_W("mkdir('%s')", path.c_str());
				return false;
			}
		}
	} else {
		int fd =
		    TEMP_FAILURE_RETRY(open(path.c_str(), O_CREAT | O_RDONLY | O_CLOEXEC, 0644));
		if (fd == -1) {
			if (errno != EROFS || !util::existsAsReg(path.c_str())) {
				PLOG_W("open('%s', O_CREAT)", path.c_str());
				return false;
			}
			return true;
		}
		close(fd);
	}
	return true;
}

static bool mountSymlink(mount_t* mpt, const std::string& dstpath) {
	LOG_D("Creating symlink: %s -> %s", mpt->src.c_str(), dstpath.c_str());
	if (symlink(mpt->src.c_str(), dstpath.c_str()) == -1) {
		if (mpt->mpt->mandatory()) {
			PLOG_E("symlink('%s' -> '%s')", mpt->src.c_str(), dstpath.c_str());
			return false;
		}
		PLOG_W("symlink('%s' -> '%s') failed (non-mandatory)", mpt->src.c_str(),
		    dstpath.c_str());
	}
	return true;
}

static bool mountWithDynamicContent(
    mount_t* mpt, const std::string& dstpath, const std::string& tmpdir) {
	static uint64_t counter = 0;
	std::string srcpath = tmpdir + "/dynamic." + std::to_string(++counter);
	defer {
		unlink(srcpath.c_str());
	};

	int fd = TEMP_FAILURE_RETRY(
	    open(srcpath.c_str(), O_CREAT | O_EXCL | O_CLOEXEC | O_WRONLY, 0644));
	if (fd == -1) {
		PLOG_W("open('%s', O_CREAT)", srcpath.c_str());
		return false;
	}

	const auto& content = mpt->mpt->src_content();
	bool write_ok = util::writeToFd(fd, content.data(), content.length());
	close(fd);

	if (!write_ok) {
		LOG_W("Failed to write %zu bytes to '%s'", content.length(), srcpath.c_str());
		return false;
	}

	mpt->flags |= MS_BIND | MS_REC | MS_PRIVATE;
	if (tryMountRW(mpt, srcpath.c_str(), dstpath.c_str()) == -1) {
		PLOG_W("mount('%s' -> '%s')", srcpath.c_str(), dstpath.c_str());
		return false;
	}

	mpt->mounted = true;
	return true;
}

static bool mountSinglePoint(mount_t* mpt, const char* newroot, const char* tmpdir) {
	LOG_D("Mounting (legacy): %s", mnt::describeMountPt(*mpt->mpt).c_str());

	if (!util::isSafeContainmentPath(mpt->dst)) {
		LOG_E("Mount destination escapes containment via '.'/'..'/NUL: %s", QC(mpt->dst));
		return false;
	}

	const std::string dstpath = std::string(newroot) + "/" + mpt->dst;
	if (!util::isSafeContainmentPath(dstpath)) {
		LOG_E("Resolved mount path escapes containment: %s", QC(dstpath));
		return false;
	}
	std::string srcpath = mpt->src.empty() ? "none" : mpt->src;

	if (!util::createDirRecursively(dstpath.c_str())) {
		LOG_W("Failed to create parent directories for '%s'", dstpath.c_str());
		return false;
	}

	if (mpt->mpt->is_symlink()) {
		return mountSymlink(mpt, dstpath);
	}

	if (!createMountTarget(dstpath, mpt->is_dir)) {
		return false;
	}

	if (!mpt->mpt->src_content().empty()) {
		return mountWithDynamicContent(mpt, dstpath, tmpdir);
	}

	if (tryMountRW(mpt, srcpath.c_str(), dstpath.c_str()) == -1) {
		if (errno == EACCES) {
			PLOG_W("mount('%s' -> '%s'): try 'chmod o+x' on source path",
			    srcpath.c_str(), dstpath.c_str());
		} else if (mpt->mpt->fstype() == "proc") {
			PLOG_W("mount('%s' -> '%s'): procfs mount may fail if /proc has "
			       "overmounts (e.g., /dev/null on /proc/kcore)",
			    srcpath.c_str(), dstpath.c_str());
		} else {
			PLOG_W("mount('%s' -> '%s')", srcpath.c_str(), dstpath.c_str());
		}
		return false;
	}

	mpt->mounted = true;
	return true;
}

static unsigned long computeRemountFlags(const mount_t& mpt, const struct statvfs& vfs) {
	struct {
		const unsigned long mount_flag;
		const unsigned long vfs_flag;
	} static const mountPairs[] = {
	    {MS_NOSUID, ST_NOSUID},
	    {MS_NODEV, ST_NODEV},
	    {MS_NOEXEC, ST_NOEXEC},
	    {MS_SYNCHRONOUS, ST_SYNCHRONOUS},
	    {MS_MANDLOCK, ST_MANDLOCK},
	    {MS_NOATIME, ST_NOATIME},
	    {MS_NODIRATIME, ST_NODIRATIME},
	    {MS_RELATIME, ST_RELATIME},
	    {MS_NOSYMFOLLOW, ST_NOSYMFOLLOW},
	};

	const unsigned long per_mountpoint_flags =
	    MS_LAZYTIME | MS_MANDLOCK | MS_NOATIME | MS_NODEV | MS_NODIRATIME | MS_NOEXEC |
	    MS_NOSUID | MS_RELATIME | MS_RDONLY | MS_SYNCHRONOUS | MS_NOSYMFOLLOW;

	unsigned long flags = MS_REMOUNT | MS_BIND | (mpt.flags & per_mountpoint_flags);
	for (const auto& i : mountPairs) {
		if (vfs.f_flag & i.vfs_flag) {
			flags |= i.mount_flag;
		}
	}
	return flags;
}

static bool remountOne(const std::string& path, const mnt::mount_t& mpt) {
	struct statvfs vfs;
	if (TEMP_FAILURE_RETRY(statvfs(path.c_str(), &vfs)) == -1) {
		PLOG_W("statvfs('%s')", path.c_str());
		return false;
	}

	unsigned long flags = computeRemountFlags(mpt, vfs);
	LOG_D("Remounting '%s' with flags: %s", path.c_str(), mnt::flagsToStr(flags).c_str());

	if (mount(path.c_str(), path.c_str(), nullptr, flags, nullptr) == -1) {
		PLOG_W("mount('%s', flags=%s)", path.c_str(), mnt::flagsToStr(flags).c_str());
		return false;
	}
	return true;
}

/*
 * Whether the jail can't reach the mount with the given mountinfo ID at path,
 * which a remount by path then can't either. Another mount covers it, as a
 * later entry's mount covers submounts of an earlier bind, or nsjail may not
 * look up the path, as below /sys/kernel/debug, which only the real root may
 * enter. The jail has at most nsjail's rights in its user namespace.
 */
static bool isUnreachable(const std::string& path, uint64_t mnt_id) {
	struct statx stx;
	if (statx(AT_FDCWD, path.c_str(), AT_NO_AUTOMOUNT, STATX_MNT_ID, &stx) == -1) {
		return errno == ENOENT || errno == EACCES;
	}
	/* Kernels before 5.8 don't report the mount ID. */
	return (stx.stx_mask & STATX_MNT_ID) && stx.stx_mnt_id != mnt_id;
}

/* A mount as /proc/self/mountinfo lists it. */
struct MountInfo {
	uint64_t id;
	std::string path;
};

/* Decodes the octal escapes, such as \040 for a space, in a mountinfo path. */
static std::string unescapeMountInfoPath(const std::string& path) {
	auto octal = [&](size_t i) { return path[i] >= '0' && path[i] <= '7'; };
	std::string out;
	out.reserve(path.size());
	for (size_t i = 0; i < path.size(); i++) {
		if (path[i] == '\\' && i + 3 < path.size() && octal(i + 1) && octal(i + 2) &&
		    octal(i + 3)) {
			out.push_back((char)(((path[i + 1] - '0') << 6) |
					     ((path[i + 2] - '0') << 3) | (path[i + 3] - '0')));
			i += 3;
		} else {
			out.push_back(path[i]);
		}
	}
	return out;
}

/* Reads the mounts at or below the canonical path from /proc/self/mountinfo. */
static bool readMountsAtOrBelow(const std::string& path, std::vector<MountInfo>* mounts) {
	FILE* f = fopen("/proc/self/mountinfo", "re");
	if (f == nullptr) {
		PLOG_W("fopen('/proc/self/mountinfo')");
		return false;
	}
	defer {
		fclose(f);
	};

	/* Field 1 (0-indexed 0) is the mount ID, field 5 (0-indexed 4) the mount point. */
	const std::string prefix = path == "/" ? path : path + "/";
	char* line = nullptr;
	size_t len = 0;
	ssize_t n;
	while ((n = getline(&line, &len, f)) != -1) {
		std::vector<std::string> fields = util::strSplit(std::string(line, n), ' ');
		if (fields.size() < 5) {
			continue;
		}
		std::string mp = unescapeMountInfoPath(fields[4]);
		if (mp == path || mp.compare(0, prefix.size(), prefix) == 0) {
			mounts->push_back({strtoull(fields[0].c_str(), nullptr, 10), mp});
		}
	}
	free(line);
	if (ferror(f)) {
		PLOG_W("reading '/proc/self/mountinfo'");
		return false;
	}
	return true;
}

static std::string normalizeMountPath(const std::string& path) {
	/* mountinfo reports canonical paths, without repeated or trailing slashes. */
	std::string normalized;
	normalized.reserve(path.size());
	for (char ch : path) {
		if (ch == '/' && !normalized.empty() && normalized.back() == '/') {
			continue;
		}
		normalized.push_back(ch);
	}
	if (normalized.size() > 1 && normalized.back() == '/') {
		normalized.pop_back();
	}
	return normalized;
}

bool remountPt(mnt::mount_t& mpt, const std::string& root_dir) {
	if (!mpt.mounted || mpt.mpt->is_symlink()) {
		return true;
	}

	const char* relative_dst = util::stripLeadingSlashes(mpt.dst.c_str());
	std::string dst_path = normalizeMountPath(
	    relative_dst[0] ? root_dir + "/" + relative_dst : root_dir);
	char* canonical_dst_path = realpath(dst_path.c_str(), nullptr);
	if (!canonical_dst_path) {
		PLOG_W("realpath('%s')", dst_path.c_str());
		return false;
	}
	dst_path = normalizeMountPath(canonical_dst_path);
	free(canonical_dst_path);
	if (!remountOne(dst_path, mpt)) {
		return false;
	}

	/*
	 * Every bind is forced recursive (MS_REC), so a bind whose source subtree
	 * contains nested mounts clones those submounts into the jail. The MS_REMOUNT
	 * above re-applies the requested per-mount flags (nosuid/nodev/noexec/...) only
	 * to the top mount, leaving nested submounts with their original
	 * suid/dev/exec-permitting attributes. Re-apply the flags to each submount so
	 * the requested restrictions cover the whole cloned subtree -- matching the
	 * recursive read-only pass and the new-mount-API backend, which applies the
	 * attributes with mount_setattr(AT_RECURSIVE).
	 */
	if (mpt.flags & MS_REC) {
		std::vector<MountInfo> mounts;
		if (!readMountsAtOrBelow(dst_path, &mounts)) {
			return false;
		}
		for (const auto& m : mounts) {
			if (m.path != dst_path && !isUnreachable(m.path, m.id) &&
			    !remountOne(m.path, mpt)) {
				return false;
			}
		}
	}
	return true;
}

std::unique_ptr<std::string> buildMountTree(nsj_t* nsj, std::vector<mnt::mount_t>* mounted_mpts) {
	if (chdir("/") == -1) {
		PLOG_E("chdir('/')");
		return nullptr;
	}

	const size_t tmpfsSize = 16 * 1024 * 1024;

	auto destdir = mnt::findWorkDir(nsj, "root");
	if (!destdir) {
		return nullptr;
	}

	if (mount("/", "/", nullptr, MS_REC | MS_PRIVATE, nullptr) == -1) {
		PLOG_E("mount('/', MS_REC|MS_PRIVATE)");
		return nullptr;
	}

	if (mount(nullptr, destdir->c_str(), "tmpfs", 0,
		("size=" + std::to_string(tmpfsSize)).c_str()) == -1) {
		PLOG_E("mount('%s', tmpfs)", destdir->c_str());
		return nullptr;
	}

	auto tmpdir = mnt::findWorkDir(nsj, "tmp");
	if (!tmpdir) {
		return nullptr;
	}

	if (mount(nullptr, tmpdir->c_str(), "tmpfs", 0,
		("size=" + std::to_string(tmpfsSize)).c_str()) == -1) {
		PLOG_E("mount('%s', tmpfs)", tmpdir->c_str());
		return nullptr;
	}

	for (const auto& proto : nsj->njc.mount()) {
		mount_t mpt = prepareMountPoint(proto);

		if (!mountSinglePoint(&mpt, destdir->c_str(), tmpdir->c_str())) {
			if (mpt.mpt->mandatory()) {
				LOG_E("Failed to mount mandatory point: %s", QC(mpt.dst));
				return nullptr;
			}
		}
		mounted_mpts->push_back(mpt);
	}

	if (!nsj->is_root_rw) {
		if (mount(destdir->c_str(), destdir->c_str(), nullptr,
			MS_REMOUNT | MS_BIND | MS_RDONLY, nullptr) == -1) {
			PLOG_E("mount('%s', MS_REMOUNT|MS_BIND|MS_RDONLY)", destdir->c_str());
			return nullptr;
		}
	}

	if (umount2(tmpdir->c_str(), MNT_DETACH) == -1) {
		PLOG_E("umount2('%s', MNT_DETACH)", tmpdir->c_str());
		return nullptr;
	}

	return destdir;
}

}  // namespace legacy
}  // namespace mnt
