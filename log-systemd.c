/**
 * Log source provider for a systemd.
 *
 * Copyright (C) 2013 Peter Wu <lekensteyn@gmail.com>
 * Licensed under GPLv3 or any latter version.
 */
#include <stdio.h>
#include <string.h>
#include <systemd/sd-journal.h>

#include "ssh-blocker.h"

/* systemd service filter for the SSH daemon */
#define MATCH "_SYSTEMD_UNIT=sshd.service"

static sd_journal *j;

#define RET_FAIL(fmt, ...) do { \
	fprintf(stderr, "log-systemd: " fmt ": %s\n", ## __VA_ARGS__, strerror(-r)); \
	return -1; \
} while (0)

int
log_open(uid_t uid, const char *filename) {
	int r;

	r = sd_journal_open(&j, SD_JOURNAL_LOCAL_ONLY);
	if (r < 0) {
		RET_FAIL("Failed to open journal");
	}

	r = sd_journal_add_match(j, MATCH, 0);
	if (r < 0) {
		RET_FAIL("Failed to restrict output to %s", MATCH);
	}

	r = sd_journal_seek_tail(j);
	if (r < 0) {
		RET_FAIL("Failed to find the end of the log");
	}

	/* systemd feature/ bug: without a sd_journal_previous,
	 * sd_journal_seek_tail has no effect */
	r = sd_journal_previous(j);
	if (r < 0) {
		RET_FAIL("Failed to move to the ned of the journal");
	}
	return 0;
}

int
log_read_line(char *buf, size_t buf_size) {
	int r;
	const char *d;
	size_t l;

	for (;;) {
		r = sd_journal_next(j);
		if (r < 0) {
			/* Failed to iterate to next entry */
			return 0;
		}

		if (r == 0) {
			/* Reached the end, let's wait for changes, and try again */
			r = sd_journal_wait(j, (uint64_t) -1);
			if (r < 0) {
				/* Failed to wait for changes */
				return 0;
			}
			continue;
		}
		break;
	}

	r = sd_journal_get_data(j, "MESSAGE", (const void **)&d, &l);
	if (r < 0) {
		/* Failed to read message field */
		return 0;
	}

	/* assume string starts with MESSAGE= */
	d += sizeof("MESSAGE=") - 1;
	l -= sizeof("MESSAGE=") - 1;

	if (l <= 0) {
		/* empty message or systemd bug ? */
		return 0;
	}

	if (l > buf_size) {
		l = buf_size - 1;
	}

	memcpy(buf, d, l);
	buf[l] = '\0';

	return l;
}

void
log_close(void) {
	sd_journal_close(j);
}
