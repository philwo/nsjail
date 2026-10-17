/*

   nsjail - config parsing
   -----------------------------------------

   Copyright 2017 Google Inc. All Rights Reserved.

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

#include "config.h"

#include <fcntl.h>
#include <google/protobuf/io/tokenizer.h>
#include <google/protobuf/io/zero_copy_stream_impl.h>
#include <google/protobuf/text_format.h>
#include <google/protobuf/util/json_util.h>
#include <stdio.h>
#include <sys/mount.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <limits>
#include <string>

#include "caps.h"
#include "cmdline.h"
#include "config.pb.h"
#include "logs.h"
#include "macros.h"
#include "mnt.h"
#include "user.h"
#include "util.h"

namespace config {

uint64_t adjustRLimit(int res, const nsjail::RLimit& rl, const uint64_t val, unsigned long mul) {
	if (rl == nsjail::RLimit::VALUE) {
		if (mul != 0 && val > std::numeric_limits<uint64_t>::max() / mul) {
			LOG_F("RLIMIT %s (%d) value overflows after applying its unit multiplier",
			    util::rLimName(res).c_str(), res);
		}
		return (val * mul);
	}
	if (rl == nsjail::RLimit::SOFT) {
		return cmdline::parseRLimit(res, "soft", mul);
	}
	if (rl == nsjail::RLimit::HARD) {
		return cmdline::parseRLimit(res, "hard", mul);
	}
	if (rl == nsjail::RLimit::INF) {
		return RLIM64_INFINITY;
	}
	LOG_F("Unknown rlimit value type for rlimit:%d", res);
	abort();
}

static bool parseInternal(nsj_t* nsj, const nsjail::NsJailConfig& njc) {
	nsj->njc.CopyFrom(njc);
	/*
	 * We need to copy the values from the protobuf message to the internal
	 * struct, because we need to perform some transformations on them.
	 */
	if (njc.has_log_fd()) {
		logs::logFile("", njc.log_fd());
	}
	if (njc.has_log_file()) {
		logs::logFile(njc.log_file(), STDERR_FILENO);
	}

	if (njc.has_log_level()) {
		switch (njc.log_level()) {
		case nsjail::LogLevel::DEBUG:
			logs::setLogLevel(logs::DEBUG);
			break;
		case nsjail::LogLevel::INFO:
			logs::setLogLevel(logs::INFO);
			break;
		case nsjail::LogLevel::WARNING:
			logs::setLogLevel(logs::WARNING);
			break;
		case nsjail::LogLevel::ERROR:
			logs::setLogLevel(logs::ERROR);
			break;
		case nsjail::LogLevel::FATAL:
			logs::setLogLevel(logs::FATAL);
			break;
		default:
			LOG_E("Unknown log_level: %d", njc.log_level());
			return false;
		}
	}

	for (ssize_t i = 0; i < njc.envar_size(); i++) {
		cmdline::addEnv(nsj, njc.envar(i));
	}
	for (ssize_t i = 0; i < njc.pass_fd_size(); i++) {
		nsj->openfds.push_back(njc.pass_fd(i));
		nsj->passfds.push_back(njc.pass_fd(i));
	}
	for (ssize_t i = 0; i < njc.uidmap_size(); i++) {
		if (!user::parseId(nsj, njc.uidmap(i).inside_id(), njc.uidmap(i).outside_id(),
			njc.uidmap(i).count(), false /* is_gid */, njc.uidmap(i).use_newidmap())) {
			return false;
		}
	}
	for (ssize_t i = 0; i < njc.gidmap_size(); i++) {
		if (!user::parseId(nsj, njc.gidmap(i).inside_id(), njc.gidmap(i).outside_id(),
			njc.gidmap(i).count(), true /* is_gid */, njc.gidmap(i).use_newidmap())) {
			return false;
		}
	}

	if (!njc.mount_proc()) {
		nsj->proc_path.clear();
	}
	if (njc.has_seccomp_policy_file()) {
		nsj->njc.set_seccomp_policy_file(njc.seccomp_policy_file());
	}

	if (njc.has_exec_bin()) {
		if (njc.exec_bin().has_path()) {
			nsj->argv.push_back(njc.exec_bin().path());
		}
		for (ssize_t i = 0; i < njc.exec_bin().arg().size(); i++) {
			nsj->argv.push_back(njc.exec_bin().arg(i));
		}
		if (njc.exec_bin().has_arg0()) {
			nsj->argv[0] = njc.exec_bin().arg0();
		}
		nsj->exec_fd = njc.exec_bin().exec_fd();
	}

	return true;
}

/* Logs TextProto parse errors with the config file's name and position */
class TextProtoErrorCollector : public google::protobuf::io::ErrorCollector {
       public:
	explicit TextProtoErrorCollector(const char* file) : file_(file) {
	}

/* protobuf < 22 (C++ 4.22) reports errors through AddError() instead of RecordError() */
#if defined(GOOGLE_PROTOBUF_VERSION) && GOOGLE_PROTOBUF_VERSION < 4022000
	void AddError(int line, int column, const std::string& message) override {
		logError(line, column, message);
	}
#else
	void RecordError(int line, int column, absl::string_view message) override {
		logError(line, column, std::string(message));
	}
#endif

       private:
	void logError(int line, int column, const std::string& message) {
		/* Errors about the whole message, such as missing required fields, have line -1 */
		if (line < 0) {
			LOG_E("%s: %s", QC(file_), message.c_str());
			return;
		}
		LOG_E("%s:%d:%d: %s", QC(file_), line + 1, column + 1, message.c_str());
	}

	const char* file_;
};

bool parseFile(nsj_t* nsj, const char* file) {
	LOG_D("Parsing configuration from %s", QC(file));

	std::string conf;
	if (!util::readFromFileToStr(file, &conf)) {
		LOG_E("Couldn't read config file %s", QC(file));
		return false;
	}
	if (conf.empty()) {
		LOG_E("Config file %s is empty", QC(file));
		return false;
	}

	/* A ProtoJSON message is an object, and a TextProto message can't start with '{' */
	nsjail::NsJailConfig njc;
	size_t start = conf.find_first_not_of(" \t\r\n");
	if (start != std::string::npos && conf[start] == '{') {
		auto status = google::protobuf::util::JsonStringToMessage(conf, &njc);
		if (!status.ok()) {
			LOG_E("Couldn't parse config file %s as ProtoJSON: %s", QC(file),
			    status.ToString().c_str());
			return false;
		}
		/* The ProtoJSON parser doesn't check required fields */
		if (!njc.IsInitialized()) {
			LOG_E("Config file %s is missing required fields: %s", QC(file),
			    njc.InitializationErrorString().c_str());
			return false;
		}
	} else {
		TextProtoErrorCollector errors(file);
		google::protobuf::TextFormat::Parser parser;
		parser.RecordErrorsTo(&errors);
		if (!parser.ParseFromString(conf, &njc)) {
			LOG_E("Couldn't parse config file %s as TextProto", QC(file));
			return false;
		}
	}

	/* Apply the config */
	if (!parseInternal(nsj, njc)) {
		LOG_W("Couldn't apply the config from %s", QC(file));
		return false;
	}
	LOG_D("Parsed config from %s:\n'%s'", QC(file), njc.DebugString().c_str());
	return true;
}

}  // namespace config
