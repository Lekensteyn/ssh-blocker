/**
 * Read SSH log messages from a FIFO pipe and block IP addresses exceeding a
 * certain threshold by adding it with ipset.
 *
 * Copyright (C) 2013 Peter Wu <lekensteyn@gmail.com>
 * Licensed under GPLv3 or any latter version.
 */
#define _GNU_SOURCE
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <signal.h>
#include "ssh-blocker.h"

#include <sys/capability.h>
#include <pwd.h>
#include <sys/prctl.h>

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
		/* ignore failure from an existing file */
		if (errno != EEXIST) {
			perror("mkfifo");
			return NULL;
		}
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

/* str does not need to be NUL-terminated */
static void
process_line(struct log_pattern *patterns,
		int patterns_count, char *str, size_t str_len) {
	int i;

	for (i = 0; i < patterns_count; i++) {
		struct in_addr addr;
		char *ip = find_ip(patterns[i].pattern, str, str_len, &addr);
		if (ip) {
			if (patterns[i].is_whitelist) {
				iplist_accept(addr);
			} else {
				iplist_block(addr);
			}
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

/* Drop privileges and become "user" */
static int
drop_privileges(const char *user) {
	/* CAP_NET_ADMIN: necessary for ipset; CAP_SETUID, CAP_SETGID: setresgid/setresguid */
	cap_value_t capability[] = { CAP_NET_ADMIN, CAP_SETUID, CAP_SETGID };
	const int ncaps =  3;
	cap_t caps;
	struct passwd *passwd;
	uid_t uid;
	gid_t gid;

	passwd = getpwnam(user);
	if (!passwd) {
		fprintf(stderr, "Cannot find user %s\n", user);
		return -1;
	}
	uid = passwd->pw_uid;
	gid = passwd->pw_gid;

	/* TODO: check capabilities and userid so program does not need to start as root */

	caps = cap_get_proc();
	if (!caps) {
		perror("Failed to get capabilities");
		return -1;
	}

	cap_clear(caps);
	cap_set_flag(caps, CAP_EFFECTIVE, ncaps, capability, CAP_SET);
	cap_set_flag(caps, CAP_PERMITTED, ncaps, capability, CAP_SET);
	if (cap_set_proc(caps)) {
		perror("Failed to lower capabilities");
		cap_free(caps);
		return -1;
	}

	/* keep caps after dropping from root */
	if (prctl(PR_SET_KEEPCAPS, 1L)) {
		perror("Failed to keep capabilities between user switches");
		cap_free(caps);
		return -1;
	}

	if (setresgid(gid, gid, gid) || setresuid(uid, uid, uid)) {
		perror("Failed to change uid/gid");
		cap_free(caps);
		return -1;
	}

	cap_clear(caps);
	cap_set_flag(caps, CAP_EFFECTIVE, 1, capability, CAP_SET);
	cap_set_flag(caps, CAP_PERMITTED, 1, capability, CAP_SET);
	if (cap_set_proc(caps)) {
		perror("Failed to drop more capabilities");
		cap_free(caps);
		return -1;
	}

	cap_free(caps);
	return 0;
}

int main(int argc, char **argv) {
	size_t patterns_count;
	struct log_pattern *patterns;
	const char *logname, *username;
	FILE *fp;

	if (argc < 3) {
		fprintf(stderr, "Usage: %s log-pipe-file username\n", argv[0]);
		return 2;
	}
	logname = argv[1];
	username = argv[2];

	if ((fp = open_log(logname)) == NULL)
		return 2;

	if (drop_privileges(username) < 0)
		return 2;

	if (!blocker_init())
		return 1;

	install_signal_handlers();
	patterns_count = patterns_init(&patterns);
	if (!patterns_count)
		return 1;

	while (active) {
		char str[1024];
		int str_len;

		str_len = read_line(fp, str, sizeof str);
		if (str_len > 0) {
			process_line(patterns, patterns_count, str, str_len);
		}
	}

	blocker_fini();
	fclose(fp);
	patterns_fini();

	return 0;
}
