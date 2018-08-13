#include <stdio.h>
#include <stdarg.h>
#include <time.h>

#include "stpm2_log.h"

static stpm2_log_level current_level = STPM2_LOG_LEVEL_TRACE;


stpm2_log_level stpm2_get_log_level(void)
{
	return current_level;
}

void stpm2_set_log_level(stpm2_log_level level)
{
	current_level = level;
}

static const char *level_names[] = {
	"ERROR",
	"WARN",
	"INFO",
	"DEBUG",
	"TRACE",
};

static const char *level_colors[] = {
	"\x1b[31m",
	"\x1b[33m",
	"\x1b[32m",
	"\x1b[36m",
	"\x1b[90m",
};

void stpm2_do_log(stpm2_log_level level, const char *file, int line, const char *fmt, ...)
{
	if (level > current_level)
		return;


	time_t t = time(NULL);
	struct tm *tm = localtime(&t);
	char buf[26];
	strftime(buf, 26, "%H:%M:%S", tm);

	fprintf(stderr, "%s %s%5s\x1b[0m \x1b[90m%10s:%-4d\x1b[0m ", buf, level_colors[level], level_names[level], file, line);

	va_list args;
	va_start(args, fmt);
	vfprintf(stderr, fmt, args);
	va_end(args);

	fprintf(stderr, "\n");
	fflush(stderr);
}
