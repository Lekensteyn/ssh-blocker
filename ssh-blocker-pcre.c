/**
 * Read SSH log messages from a FIFO pipe and block IP addresses exceeding a
 * certain threshold by adding it with ipset.
 *
 * Copyright (C) 2013 Peter Wu <lekensteyn@gmail.com>
 * Licensed under GPLv3 or any latter version.
 *
 * Wishlist: capabilities should get support for inherited process capabilities.
 */

#include <pcre.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <signal.h>
#include "ssh-blocker.h"

/* callback when an IP address is matched */
typedef void (*fn_action_t)(struct in_addr addr, char *ip);

#define IP_DIGITS "(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])"
#define IP_PATTERN "(" IP_DIGITS "\\." IP_DIGITS "\\." IP_DIGITS "\\." IP_DIGITS ")"

static pcre *
compile(const char *pattern) {
	int options = PCRE_ANCHORED;
	const char *error;
	int erroffset;
	pcre *re;

	re = pcre_compile(pattern, options, &error, &erroffset, NULL);
	if (re == NULL) {
		fprintf(stderr, "PCRE compilation failed at offset %d: %s\n", erroffset, error);
		exit(1);
	}

	return re;
}

static char *
substring(const char *str, int start, int end) {
	size_t len = end - start;
	char *p = malloc(len + 1);
	if (!p) {
		perror("malloc in substring");
		abort();
	}
	memcpy(p, str + start, len);
	p[len] = 0;
	return p;
}

/* if a non-NULL string is returned, it must be free'd */
static char *
find_ip(const pcre *code, const char *subject, int length, struct in_addr *addr) {
	int rc, options = 0;
	/* multiple of 3, first pair match whole string, next pairs are groups */
	int ovector[3 * 8];
	char *group1;

	rc = pcre_exec(code, NULL, subject, length, 0, options, ovector, sizeof(ovector));
	if (rc == 0) {
		fprintf(stderr, "Not enough space to hold groups in pattern\n");
		exit(1);
	}
	//printf("Number of groups including match of everything: %d\n", rc);
	if (rc < 2) {
		/* matching error, e.g. too little groups */
		return NULL;
	}
	group1 = substring(subject, ovector[2], ovector[3]);
	if (inet_pton(AF_INET, group1, addr) != 1) {
		free(group1);
		return NULL;
	}
	return group1;
}

static FILE *
open_log(const char *filename) {
	FILE *fp;
	struct stat statbuf;

	if (mkfifo(filename, S_IRUSR | S_IWUSR)) {
		if (errno == EEXIST)
			fprintf(stderr, "Remove the log pipe file '%s' first\n", filename);
		else
			perror("mkfifo");
		return NULL;
	}

	/* open R/W in order to avoid EOF */
	fp = fopen(filename, "r+");
	if (!fp) {
		perror("fopen");
		return NULL;
	}

	do {
		if (fstat(fileno(fp), &statbuf) < 0) {
			perror("fstat");
			break;
		}

		if (!S_ISFIFO(statbuf.st_mode)) {
			fprintf(stderr, "Log file must be a FIFO\n");
			break;
		}

		if (statbuf.st_mode & (S_IWOTH)) {
			fprintf(stderr, "Log file must not be world-writable\n");
			break;
		}

		if (statbuf.st_uid != 0 && statbuf.st_uid != getuid()) {
			fprintf(stderr, "Log file must be owned by root or the owner of this process\n");
			break;
		}

		return fp;
	} while (0);

	fclose(fp);
	return NULL;
}

static pcre **
compile_patterns(const char **regex, int count) {
	int i;
	pcre **patterns;

	patterns = malloc(count * sizeof(pcre *));
	if (!patterns) {
		perror("malloc");
		abort();
	}
	for (i = 0; i < count; i++) {
		patterns[i] = compile(regex[i]);
	}

	return patterns;
}

static void
free_patterns(pcre **patterns, int patterns_count) {
	int i;

	for (i = 0; i < patterns_count; i++) {
		pcre_free(patterns[i]);
	}
	free(patterns);
}

static int read_line(FILE *fp, char *buf, size_t buf_size) {
	int len;

	if (fgets(buf, buf_size, fp) == NULL)
		return 0;

	len = strlen(buf);
	if (len > 0) {
		if (buf[len - 1] == '\n')
			buf[--len] = 0;
	}

	return len;
}

static void
act_block(struct in_addr addr, char *ip) {
	printf("Blocked: %s\n", ip);
	iplist_block(addr);
}

static void
act_accept(struct in_addr addr, char *ip) {
	printf("Accepted: %s\n", ip);
	iplist_accept(addr);
}

/* str does not need to be NUL-terminated */
static void
process_line(pcre **patterns, fn_action_t *actions, int patterns_count,
		char *str, size_t str_len) {
	int i;

	for (i = 0; i < patterns_count; i++) {
		struct in_addr addr;
		char *ip = find_ip(patterns[i], str, str_len, &addr);
		if (ip) {
			actions[i](addr, ip);
			free(ip);
			break;
		}
	}
}

/* set to 0 to break the main loop */
static int active = 1;

static void sa_quit(int signal_no) {
	active = 0;
	fprintf(stderr, "Received signal %i - shutting down\n", signal_no);
}

static void install_signal_handlers() {
	struct sigaction action;
	action.sa_handler = sa_quit;
	sigemptyset(&action.sa_mask);
	action.sa_flags = 0;
	if (sigaction(SIGTERM, &action, NULL) < 0)
		perror("sigaction(SIGTERM)");
	if (sigaction(SIGINT, &action, NULL) < 0)
		perror("sigaction(SIGINT)");
}

int main(int argc, char **argv) {
	const char *regexes[] = {
		"Invalid user .{0,100} from " IP_PATTERN "$",
		"User .{0,100} from " IP_PATTERN " not allowed because not listed in AllowUsers$",
		"Accepted publickey for .{0,100} from " IP_PATTERN " port [0-9]{1,5} ssh2$"
	};
	fn_action_t actions[] = {
		act_block,
		act_block,
		act_accept,
	};
	int patterns_count = sizeof(regexes) / sizeof(*regexes);
	pcre **patterns;
	const char *logname;
	FILE *fp;

	if (argc < 2) {
		fprintf(stderr, "Usage: %s log-pipe-file\n", argv[0]);
		return 2;
	}
	logname = argv[1];

	if (!blocker_init())
		return 1;

	if ((fp = open_log(logname)) == NULL)
		return 2;

	install_signal_handlers();
	patterns = compile_patterns(regexes, patterns_count);

	while (active) {
		char str[1024];
		int str_len;

		str_len = read_line(fp, str, sizeof str);
		if (str_len > 0) {
			process_line(patterns, actions, patterns_count, str, str_len);
		}
	}

	blocker_fini();
	fclose(fp);
	free_patterns(patterns, patterns_count);

	return 0;
}
