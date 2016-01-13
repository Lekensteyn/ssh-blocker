/**
 * Log source provider for a pipe.
 *
 * Copyright (C) 2013-2016 Peter Wu <peter@lekensteyn.nl>
 * Licensed under GPLv3 or any latter version.
 */
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <sys/file.h>
#include "ssh-blocker.h"

static FILE *fp;

/* returns 0 on success and non-zero on failure */
int
log_open(uid_t uid, const char *filename) {
	struct stat statbuf;

	if (mkfifo(filename, S_IRUSR | S_IWUSR)) {
		/* ignore failure from an existing file */
		if (errno != EEXIST) {
			perror("mkfifo");
			return -1;
		}
	}

	/* open R/W in order to avoid EOF */
	fp = fopen(filename, "r+");
	if (!fp) {
		perror("fopen");
		return -1;
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

		if (statbuf.st_uid != 0 && statbuf.st_uid != uid) {
			fprintf(stderr, "Log file must be owned by root or the owner of this process\n");
			break;
		}

		if (flock(fileno(fp), LOCK_EX | LOCK_NB) < 0) {
			perror("Cannot lock for reading");
			break;
		}

		return 0;
	} while (0);

	fclose(fp);
	fp = NULL;
	return -1;
}

int
log_read_line(char *buf, size_t buf_size) {
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

void
log_close(void) {
	if (fp) {
		fclose(fp);
		fp = NULL;
	}
}
