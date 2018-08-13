#ifndef __STPM2_LOG_H__
#define __STPM2_LOG_H__

/* Source: https://stackoverflow.com/questions/8487986/file-macro-shows-full-path */
#define __FILENAME__ (strrchr(__FILE__, '/') ? strrchr(__FILE__, '/') + 1 : __FILE__)

#define LOG_ERROR(...) stpm2_do_log(STPM2_LOG_LEVEL_ERR, __FILENAME__, __LINE__, __VA_ARGS__)
#define LOG_WARN(...) stpm2_do_log(STPM2_LOG_LEVEL_WARN, __FILENAME__, __LINE__, __VA_ARGS__)
#define LOG_INFO(...) stpm2_do_log(STPM2_LOG_LEVEL_INFO, __FILENAME__, __LINE__, __VA_ARGS__)
#define LOG_DEBUG(...) stpm2_do_log(STPM2_LOG_LEVEL_DEBUG, __FILENAME__, __LINE__, __VA_ARGS__)
#define LOG_TRACE(...) stpm2_do_log(STPM2_LOG_LEVEL_TRACE, __FILENAME__, __LINE__, __VA_ARGS__)

typedef enum {
	STPM2_LOG_LEVEL_ERR,
	STPM2_LOG_LEVEL_WARN,
	STPM2_LOG_LEVEL_INFO,
	STPM2_LOG_LEVEL_DEBUG,
	STPM2_LOG_LEVEL_TRACE,
} stpm2_log_level;

stpm2_log_level stpm2_get_log_level(void);
void stpm2_set_log_level(stpm2_log_level level);

void stpm2_do_log(stpm2_log_level level, const char *file, int line, const char *fmt, ...);

#endif /* __STPM2_LOG_H__ */
