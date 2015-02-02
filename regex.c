/**
 * Regular expressions for matching IP addresses from log lines.
 *
 * Copyright (C) 2013 Peter Wu <lekensteyn@gmail.com>
 * Licensed under GPLv3 or any latter version.
 */
#include "ssh-blocker.h"

/* Note: when introducing new groups, be sure to increase REGEX_MAX_GROUPS in
 * ssh-blocker.h */
#if 0
static struct log_pattern matches[] = {
	{
		.regex = "Invalid user .{0,100} from " IP_PATTERN "$",
	}, {
		.regex = "User .{0,100} from " IP_PATTERN " not allowed because not listed in AllowUsers$",
	}, {
		.regex = "Accepted publickey for .{0,100} from " IP_PATTERN " port [0-9]{1,5} ssh2$",
		.is_whitelist = true,
	},
};
#endif

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

void
pattern_fini(pcre **pattern) {
	if (*pattern) {
		pcre_free(*pattern);
		*pattern = NULL;
	}
}
