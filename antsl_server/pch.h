#pragma once

#include "spdlog//async.h"
#include "spdlog/fmt/bin_to_hex.h"
#include "spdlog/fmt/fmt.h"
#include "spdlog/sinks/basic_file_sink.h"
#include "spdlog/sinks/stdout_color_sinks.h"
#include "spdlog/spdlog.h"

extern const char *AN_STDOUT_COLOR_NAME;
//
//#define AN_STDOUT_INFO(t) spdlog::get(AN_STDOUT_COLOR_NAME)->info(t);
//#define AN_STDOUT_ERROR(t) spdlog::get(AN_STDOUT_COLOR_NAME)->error(t);
//
//extern std::shared_ptr<spdlog::logger> g_console;

//日志操作类
namespace anlog {
	using anlogger = std::shared_ptr<spdlog::logger>;
	extern anlogger& getlogger();
}
