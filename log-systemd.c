/**
 * Log source provider for a systemd.
 *
 * Copyright (C) 2013-2016 Peter Wu <peter@lekensteyn.nl>
 * Licensed under GPLv3 or any latter version.
 */
#include <stdio.h>
#include <string.h>
#include <systemd/sd-journal.h>
#include <poll.h>

#include "ssh-blocker.h"

/* systemd service filter for the SSH daemon */
static const char *matches[] = {
	"_SYSTEMD_UNIT=sshd.service",     /* Arch Linux */
	"_SYSTEMD_UNIT=ssh.service",      /* Debian */
};

static sd_journal *j;

#define RET_FAIL(fmt, ...) do { \
	fprintf(stderr, "log-systemd: " fmt ": %s\n", ## __VA_ARGS__, strerror(-r)); \
	return -1; \
} while (0)

static struct pollfd log_poller;

int
log_open(uid_t uid, const char *filename) {
	int r;
	(void) uid; (void) filename;
	unsigned i;

	r = sd_journal_open(&j, SD_JOURNAL_LOCAL_ONLY | SD_JOURNAL_SYSTEM);
	if (r < 0) {
		RET_FAIL("Failed to open journal");
	}

	for (i = 0; i < sizeof(matches) / sizeof(*matches); i++) {
		r = sd_journal_add_match(j, matches[i], 0);
		if (r < 0) {
			RET_FAIL("Failed to restrict output to %s", matches[i]);
		}
	}

	r = sd_journal_seek_tail(j);
	if (r < 0) {
		RET_FAIL("Failed to find the end of the log");
	}

	/* systemd feature/ bug: without a sd_journal_previous,
	 * sd_journal_seek_tail has no effect */
	r = sd_journal_previous(j);
	if (r < 0) {
		RET_FAIL("Failed to move to the end of the journal");
	}

	memset(&log_poller, 0, sizeof log_poller);
	log_poller.fd = sd_journal_get_fd(j);
	log_poller.events = POLLIN;

	if (log_poller.fd < 0) {
		RET_FAIL("Failed to get journal fd");
	}

	return 0;
}

int
log_read_line(char *buf, size_t buf_size) {
	int r;
	const char *d;
	size_t l;

	r = sd_journal_next(j);
	if (r < 0) {
		/* Failed to iterate to next entry */
		return 0;
	}

	if (r == 0) {
		/* Reached the end, let's wait for changes, and try again */
		if (poll(&log_poller, 1, -1) < 0) {
			/* interrupted */
			return 0;
		}

		sd_journal_process(j);

		return 0;
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
	if (j) {
		sd_journal_close(j);
		j = NULL;
	}
}
