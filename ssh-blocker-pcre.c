/**
 * Read SSH log messages from a FIFO pipe and block IP addresses exceeding a
 * certain threshold by adding it with ipset.
 *
 * Copyright (C) 2013-2016 Peter Wu <peter@lekensteyn.nl>
 * Licensed under GPLv3 or any latter version.
 */
#define _GNU_SOURCE
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <assert.h>
#include "ssh-blocker.h"

#include <sys/capability.h>
#include <pwd.h>
#include <sys/prctl.h>

#ifdef HAVE_CONFIG_H
#   include "config.h"
#endif

/* returns true if a valid IP address is matched, false otherwise. 0.0.0.0 is
 * considered an invalid IP address */
static bool
find_ip(const pcre *code, const char *subject, int length, struct in_addr *addr) {
	int rc, options = 0;
	/* +1 for matching substring, a.k.a. $0 */
	int ovector[3 * (1 + REGEX_MAX_GROUPS)];
	char ip[INET_ADDRSTRLEN];

	rc = pcre_exec(code, NULL, subject, length, 0, options,
			ovector, sizeof(ovector) / sizeof(*ovector));
	/* if 0, there was not enough space... */
	assert(rc != 0);

	if (rc < 2) {
		/* matching error, e.g. too little groups */
		return false;
	}

	if (pcre_copy_named_substring(code, subject, ovector, rc, "ip",
			ip, sizeof ip) < 0) {
		/* Hmm, "ip" is not defined as capture group? */
		return false;
	}

	return inet_pton(AF_INET, ip, addr) == 1 && addr->s_addr != 0;
}

/* str does not need to be NUL-terminated */
static void
process_line(struct log_pattern *patterns,
		int patterns_count, char *str, size_t str_len) {
	int i;

	for (i = 0; i < patterns_count; i++) {
		struct in_addr addr;
		if (find_ip(patterns[i].pattern, str, str_len, &addr)) {
			if (patterns[i].is_whitelist) {
				iplist_accept(addr);
			} else {
				iplist_block(addr);
			}
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
drop_privileges(uid_t uid, gid_t gid) {
	/* CAP_NET_ADMIN: necessary for ipset; CAP_SETUID, CAP_SETGID: setresgid/setresguid */
	cap_value_t capability[] = { CAP_NET_ADMIN, CAP_SETUID, CAP_SETGID };
	const int ncaps =  3;
	cap_t caps;

	caps = cap_get_proc();
	if (!caps) {
		perror("Failed to get capabilities");
		return -1;
	}

	if (getuid() != uid) {
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
	const char *program = argv[0];
	bool daemonize = false;
	size_t patterns_count;
	struct log_pattern *patterns;
	const char *username;
	const char *logname = NULL;
	struct passwd *passwd;
	uid_t uid;
	gid_t gid;

	if (argc > 2 && strcmp(argv[1], "-d") == 0) {
		daemonize = true;
		--argc;
		++argv;
	}

#ifdef HAVE_SYSTEMD
	if (argc < 2) {
		printf("Usage: %s username\n", program);
#else
	if (argc < 3) {
		printf("Usage: %s username log-pipe-filename\n", program);
#endif
		puts(PACKAGE_STRING " built on " __DATE__);
		puts("Copyright (c) 2013-2016 Peter Wu");
		return 2;
	}
	username = argv[1];
#ifndef HAVE_SYSTEMD
	logname = argv[2];
#endif

	passwd = getpwnam(username);
	if (!passwd) {
		fprintf(stderr, "Cannot find user %s\n", username);
		return 2;
	}
	uid = passwd->pw_uid;
	gid = passwd->pw_gid;

	if (log_open(uid, logname))
		return 2;

	if (drop_privileges(uid, gid) < 0)
		return 2;

	if (!blocker_init())
		return 1;

	patterns_count = patterns_init(&patterns);
	if (!patterns_count)
		return 1;

	if (daemonize && daemon(0, 0)) {
		perror("Failed to daemonize");
		return 1;
	}

	install_signal_handlers();

	while (active) {
		char str[1024];
		int str_len;

		str_len = log_read_line(str, sizeof str);
		if (str_len > 0) {
			process_line(patterns, patterns_count, str, str_len);
		}
	}

	blocker_fini();
	log_close();
	patterns_fini();

	return 0;
}
