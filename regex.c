/**
 * Regular expressions for matching IP addresses from log lines.
 *
 * Copyright (C) 2013 Peter Wu <lekensteyn@gmail.com>
 * Licensed under GPLv3 or any latter version.
 */
#include "ssh-blocker.h"

#define IP_DIGITS "(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])"
#define IP_PATTERN "(" IP_DIGITS "\\." IP_DIGITS "\\." IP_DIGITS "\\." IP_DIGITS ")"

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

static size_t patterns_count = sizeof(matches) / sizeof(*matches);

static pcre *
compile(const char *pattern) {
	int options = PCRE_ANCHORED;
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

size_t
patterns_init(struct log_pattern **dst) {
	size_t i;

	for (i = 0; i < patterns_count; i++) {
		struct log_pattern *match = &matches[i];
		match->pattern = compile(match->regex);
		if (!match->pattern) {
			patterns_fini();
			return 0;
		}
	}

	*dst = matches;

	return patterns_count;
}

void
patterns_fini(void) {
	size_t i;

	for (i = 0; i < patterns_count; i++) {
		if (matches[i].pattern) {
			pcre_free(matches[i].pattern);
			matches[i].pattern = NULL;
		}
	}
}
