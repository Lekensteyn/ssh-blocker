/**
 * Read SSH log messages from a FIFO pipe and block IP addresses exceeding a
 * certain threshold by adding it with ipset.
 *
 * Copyright (C) 2013 Peter Wu <lekensteyn@gmail.com>
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
#include <search.h>
#include <getopt.h>

/* returns
 *    0 if there is no match,
 *    1 if a whitelist IP is matched,
 *    2 if a blacklist IP is matched */
static int
find_ip(const pcre *pattern, const char *subject, int length, struct in_addr *addr) {
	int rc, options = 0;
	/* +1 for matching substring, a.k.a. $0 */
	int ovector[3 * (1 + REGEX_MAX_GROUPS)];
	char ip[INET_ADDRSTRLEN];
	int result = 0;

	rc = pcre_exec(pattern, NULL, subject, length, 0, options,
						ovector, sizeof(ovector) / sizeof(int));

	/* if 0, there was not enough space... */
	assert(rc != 0);

	if (rc < 2) {
		/* matching error, e.g. too few groups */
		return 0;
	}

	/* check whether match is white or black */
	if (pcre_copy_named_substring(pattern, subject, ovector, rc, "wip",
											ip, sizeof ip) >= 0) {
		result = 1;
	}
	else if (pcre_copy_named_substring(pattern, subject, ovector, rc, "bip",
												  ip, sizeof ip) >= 0) {
		result = 2;
	}

	/* convert string to ip */
	if (inet_pton(AF_INET, ip, addr) != 1 || addr->s_addr == 0) {
		fprintf(stderr, "IP format unknown\n");
		return 0;
	}
	else {
		return result;
	}
}

/* str does not need to be NUL-terminated */
static void
process_line(const pcre *pattern, char *str, size_t str_len) {
	struct in_addr addr;
	switch (find_ip(pattern, str, str_len, &addr)) {
		case 1:
			iphash_accept(addr);
			break;
		case 2:
			iphash_block(addr);
			break;
	};
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

void usage(const char *program) {
	fprintf(stderr,
		"Usage: %s [options]\n"
		"Either short or long options are allowed.\n"
		"  -d|--daemonize  Daemonize this programs process.\n"
#ifdef HAVE_SYSTEMD
		"  -s|--systemd    Use systemd journal as log input.\n"
#endif
		"  -l|--logpipe    Name of the log pipe for input.\n"
		"  -r|--remember   Period during which an IP address is remembered for blacklisting (default: %d).\n"
		"  -t|--threshold  Threshold that needs to be reached before an IP address is blacklisted (default: %d).\n"
		"  -u|--username   User under whose privileges this program runs."
		"  -w|--whitelist  Name of the ipset for whitelisted IP addresses (default: %s).\n"
		"  -b|--blacklist  Name of the ipset for blacklisted IP addresses (default: %s)\n"
		"  -h|--help       Display this short inlined help screen.\n"
		"  -v|--version    Display the release number\n",
		program, REMEMBER_TIME, MATCH_THRESHOLD, SETNAME_WHITELIST, SETNAME_BLACKLIST);
}

int main(int argc, char **argv) {
	const char *program = argv[0];

	char  c;
	bool  daemonize;
	bool  systemd;
	char *username;
	char *logname;

	struct passwd *passwd;
	uid_t          uid;
	gid_t          gid;
	pcre          *pattern;

	struct option opts[] = {
		{"blacklist", 1, 0, 'b'},
		{"daemonize", 0, 0, 'd'},
		{"logpipe",   1, 0, 'l'},
		{"remember",  1, 0, 'r'},
#ifdef HAVE_SYSTEMD
		{"systemd",   0, 0, 's'},
#endif
		{"threshold", 1, 0, 't'},
		{"username",  1, 0, 'u'},
		{"whitelist", 1, 0, 'b'},
		{"help",      0, 0, 'h'},
		{"version",   0, 0, 'v'},
		{0, 0, 0, 0}
	};

	/* set defaults */
	daemonize = false;
	systemd   = false;
	logname   = NULL;
	username  = NULL;
	remember  = REMEMBER_TIME;
	threshold = MATCH_THRESHOLD;
	whitelist = SETNAME_WHITELIST;
	blacklist = SETNAME_BLACKLIST;

	while ((c = getopt_long(argc, argv, "b:dl:r:st:u:w:hv", opts, NULL)) != EOF) {
		switch (c) {
			case 'b':
				blacklist = optarg;
				break;
			case 'd':
				daemonize = true;
				break;
			case 'l':
				logname = optarg;
				break;
			case 'r':
				remember = atoi(optarg);
				break;
			case 's':
				systemd = true;
				break;
			case 't':
				threshold = atoi(optarg);
				break;
			case 'u':
				username = optarg;
				break;
			case 'w':
				whitelist = optarg;
				break;
			case 'h':
				usage(program);
				exit(0);
				break;
			case 'v':
				fprintf(stderr,
						  PACKAGE_STRING " built on " __DATE__ "\n"
						  "Copyright (c) 2013 Peter Wu\n");
				exit(0);
				break;
			default:
				fprintf(stderr, "Error: Unhandled option %d.\n", c);
				exit(1);
		};
	}

	if (optind < argc) {
		fprintf(stderr, "Unexpected arguments: ");
		while (optind < argc)
			fprintf(stderr, "%s ", argv[optind++]);
		fprintf(stderr, "\n");
	}

	/* check for username */
	if (username == NULL) {
		fprintf(stderr, "Error: --username needed.\n");
		exit(1);
	}

	/* check if log input arguments are set correctly */
#ifdef HAVE_SYSTEMD
	if (systemd == false && logname == NULL) {
		fprintf(stderr, "Error: Either use --systemd or set --logname.\n");
#else
	if (logname == NULL) {
		fprintf(stderr, "Error: --logname needed.\n");
#endif
		exit(1);
	}

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

	if ((pattern = pattern_compile(SSH_PATTERN)) == NULL) {
		return 1;
	}

	if (daemonize && daemon(0, 0)) {
		perror("Failed to daemonize");
		return 1;
	}

	/* initialize hash table */
	hcreate(IPHASH_LENGTH);

	install_signal_handlers();

	while (active) {
		char str[1024];
		int str_len;

		str_len = log_read_line(str, sizeof str);
		if (str_len > 0) {
			process_line(pattern, str, str_len);
		}
	}

	/* TBD: free keys and data
	 *		  on program exit, the kernel reclaims all allocated
	 *		  memory, so this is not strictly necessary */

	/* initialize hash table */
	hdestroy();

	blocker_fini();
	log_close();
	pattern_fini(&pattern);

	return 0;
}
