#include <stdio.h>
#include <stdarg.h>
#include <time.h>

#include <stpm2_log.h>

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

static void add_localtime(char *buf, size_t size)
{
	time_t t = time(NULL);
	struct tm *tm = localtime(&t);
	strftime(buf, 26, "%H:%M:%S", tm);
}

void stpm2_do_log(stpm2_log_level level, const char *file, int line, const char *fmt, ...)
{
	if (level > current_level)
		return;

	char buf[26];
	add_localtime(buf, sizeof(buf));

	fprintf(stderr, "%s %s%5s\x1b[0m \x1b[90m%20s:%-4d\x1b[0m ", buf, level_colors[level], level_names[level], file, line);

	va_list args;
	va_start(args, fmt);
	vfprintf(stderr, fmt, args);
	va_end(args);

	fprintf(stderr, "\n");
	fflush(stderr);
}

void stpm2_do_log_hexdump(stpm2_log_level level, const char *file, int line, char *header, unsigned char *buf, size_t len)
{
	if (level > current_level)
		return;

	char tbuf[26];
	add_localtime(tbuf, sizeof(buf));

	fprintf(stderr, "%s %s%5s\x1b[0m \x1b[90m%20s:%-4d\x1b[0m %s:\n", tbuf, level_colors[level], level_names[level], file, line, header);

	fprintf(stderr, "                                         | 0000: ");
	for (size_t i = 0; i < len; i++) {
		fprintf(stderr, "%02x", buf[i]);
		if (((i + 1) % 16) == 0 && (i + 1) < len) {
			fprintf(stderr, "\n                                         | %04zx: ", (i + 1));
		}
	}
	fprintf(stderr, "\n");
	fflush(stderr);
}

