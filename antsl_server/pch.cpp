#include "pch.h"



const char *AN_STDOUT_COLOR_NAME = "console";
//��־��ʼ��
anlog::anlogger& anlog::getlogger() {
	static anlog::anlogger g_anlog = spdlog::stdout_color_mt(AN_STDOUT_COLOR_NAME);

	return g_anlog;
}