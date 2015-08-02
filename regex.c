/**
 * Regular expressions for matching IP addresses from log lines.
 *
 * Copyright (C) 2013 Peter Wu <lekensteyn@gmail.com>
 * Licensed under GPLv3 or any latter version.
 */
#include "ssh-blocker.h"

/* Note: when introducing new groups, be sure to increase REGEX_MAX_GROUPS in
 * ssh-blocker.h */

#define USER "(?:[a-z_][a-z0-9_-]*[$]?)"
#define IP_ELEMENT "(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])"
#define IP IP_ELEMENT "\\." IP_ELEMENT "\\." IP_ELEMENT "\\." IP_ELEMENT
#define WHITELIST_IP "(?<wip>" IP ")"
#define BLACKLIST_IP "(?<bip>" IP ")"

const char *ssh_pattern =
	"Invalid user " USER " from " BLACKLIST_IP "$" "|"
	"User " USER " from " BLACKLIST_IP " not allowed because not listed in AllowUsers$" "|"
	"Accepted publickey for " USER " from " WHITELIST_IP " port [0-9]{1,5} ssh2$";

pcre *
pattern_compile(const char *pattern) {
	int options = PCRE_NO_AUTO_CAPTURE | PCRE_DUPNAMES;
	const char *error;
	int erroffset;
	pcre *re;
	re = pcre_compile(pattern, options, &error, &erroffset, NULL);
	if (re == NULL) {
		fprintf(stderr, "PCRE compilation failed at offset %d: %s\n", erroffset, error);
		return NULL;
	}

	return re;
}
