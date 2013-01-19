/**
 * Utilities for ipset management.
 *
 * Copyright (C) 2013 Peter Wu <lekensteyn@gmail.com>
 * Licensed under GPLv3 or any latter version.
 */

#include "ssh-blocker.h"
#include <unistd.h>
#include <assert.h>
#include <libipset/types.h>
#include <libipset/session.h>
#include <libipset/data.h>
#include <stdint.h>

static struct ipset_session *session;

/**
 * This function was designed for three values of cmd:
 * CMD_TEST: true if exists, false if not exists (or set name not found)
 * CMD_ADD: true if added, false if error occurred (set name not found?)
 * CMD_DEL: true if deleted, false if error occurred (set name not found?)
 */
static bool
try_ipset_cmd(enum ipset_cmd cmd, const char *setname,
		const struct in_addr *addr) {
	const struct ipset_type *type;
	uint8_t family;
	int r;
	r = ipset_session_data_set(session, IPSET_SETNAME, setname);
	/* since the IPSET_SETNAME option is valid, this should never fail */
	assert(r == 0);

	type = ipset_type_get(session, cmd);
	if (type == NULL) {
		/* possible reasons for failure: set name does not exist */
		return false;
	}

	family = NFPROTO_IPV4;
	ipset_session_data_set(session, IPSET_OPT_FAMILY, &family);
	ipset_session_data_set(session, IPSET_OPT_IP, addr);

	r = ipset_cmd(session, cmd, /*lineno*/ 0);
	/* assume that errors always occur if NOT in set. To do it otherwise,
	 * see lib/session.c for IPSET_CMD_TEST in ipset_cmd */
	return r == 0;
}

static bool
try_ipset_create(const char *setname, const char *typename, uint32_t timeout) {
	const struct ipset_type *type;
	uint8_t family;
	int r;
	r = ipset_session_data_set(session, IPSET_SETNAME, setname);
	/* since the IPSET_SETNAME option is valid, this should never fail */
	assert(r == 0);

	ipset_session_data_set(session, IPSET_OPT_TYPENAME, typename);

	type = ipset_type_get(session, IPSET_CMD_CREATE);
	if (type == NULL) {
		return false;
	}

	ipset_session_data_set(session, IPSET_OPT_TYPE, type);
	ipset_session_data_set(session, IPSET_OPT_TIMEOUT, &timeout);
	family = NFPROTO_IPV4;
	ipset_session_data_set(session, IPSET_OPT_FAMILY, &family);

	r = ipset_cmd(session, IPSET_CMD_CREATE, /*lineno*/ 0);
	return r == 0;
}

void do_block(const struct in_addr addr) {
	try_ipset_cmd(IPSET_CMD_ADD, SETNAME_BLACKLIST, &addr);
}

void do_unblock(const struct in_addr addr) {
	try_ipset_cmd(IPSET_CMD_DEL, SETNAME_BLACKLIST, &addr);
}

bool is_blocked(const struct in_addr addr) {
	return try_ipset_cmd(IPSET_CMD_TEST, SETNAME_BLACKLIST, &addr);
}

void blocker_init(void) {
	ipset_load_types();

	session = ipset_session_init(printf);
	if (!session) {
		fprintf(stderr, "Cannot initialize ipset session.\n");
		abort();
	}

	/* return success on attempting to add an existing / remove an
	 * non-existing rule */
	ipset_envopt_parse(session, IPSET_ENV_EXIST, NULL);

	/* WARNING: this call will FAIL if an existing setname exist with
	 * different parameters (e.g. a different timeout value)! */
	if (!try_ipset_create(SETNAME_BLACKLIST, TYPENAME, BLOCK_TIME)) {
		fprintf(stderr, "Failed to create %s: %s\n", SETNAME_BLACKLIST,
				ipset_session_error(session));
		fprintf(stderr, "A setname with different parameters possibly exists.");
		abort();
	}
}

void blocker_fini(void) {
	ipset_session_fini(session);
}
