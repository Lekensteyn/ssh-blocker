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
#include <stdio.h>

static struct ipset_session *session;

/**
 * This function was designed for three values of cmd:
 * CMD_TEST: true if exists, false if not exists (or set name not found)
 * CMD_ADD: true if added, false if error occurred (set name not found?)
 * CMD_DEL: true if deleted, false if error occurred (set name not found?)
 */
static bool
try_ipset_cmd(enum ipset_cmd cmd, const char *setname,
		const struct in_addr *addr, uint32_t timeout) {
	const struct ipset_type *type;
	uint8_t family;
	int r;
	r = ipset_session_data_set(session, IPSET_SETNAME, setname);
	/* since the IPSET_SETNAME option is valid, this should never fail */
	assert(r == 0);

	type = ipset_type_get(session, cmd);
	if (type == NULL) {
		fprintf(stderr, "possible reasons for failure: set name does not exist\n");
		return false;
	}

	family = NFPROTO_IPV4;
	ipset_session_data_set(session, IPSET_OPT_FAMILY, &family);
	ipset_session_data_set(session, IPSET_OPT_IP, addr);
	if (timeout)
		ipset_session_data_set(session, IPSET_OPT_TIMEOUT, &timeout);

	r = ipset_cmd(session, cmd, /*lineno*/ 0);
	/* assume that errors always occur if NOT in set. To do it otherwise,
	 * see lib/session.c for IPSET_CMD_TEST in ipset_cmd */
	return r == 0;
}

static bool
try_ipset_create(const char *setname, const char *typename) {
	const struct ipset_type *type;
	uint32_t timeout;
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

	timeout = 0; /* timeout support, but default to infinity */
	ipset_session_data_set(session, IPSET_OPT_TIMEOUT, &timeout);
	ipset_session_data_set(session, IPSET_OPT_TYPE, type);
	family = NFPROTO_IPV4;
	ipset_session_data_set(session, IPSET_OPT_FAMILY, &family);

	r = ipset_cmd(session, IPSET_CMD_CREATE, /*lineno*/ 0);
	return r == 0;
}

static bool
has_ipset_setname(const char *setname) {
	ipset_session_data_set(session, IPSET_SETNAME, setname);
	return ipset_cmd(session, IPSET_CMD_HEADER, 0) == 0;
}

void do_block(const struct in_addr addr) {
	try_ipset_cmd(IPSET_CMD_ADD, blacklist, &addr, blacktime);
}

void do_unblock(const struct in_addr addr) {
	try_ipset_cmd(IPSET_CMD_DEL, blacklist, &addr, 0);
}

void do_whitelist(const struct in_addr addr) {
	try_ipset_cmd(IPSET_CMD_ADD, whitelist, &addr, whitetime);
}

bool is_whitelisted(const struct in_addr addr) {
	return try_ipset_cmd(IPSET_CMD_TEST, whitelist, &addr, 0);
}

bool blocker_init(void) {
	ipset_load_types();

	session = ipset_session_init(printf);
	if (!session) {
		fprintf(stderr, "Cannot initialize ipset session.\n");
		return false;
	}

	/* return success on attempting to add an existing / remove an
	 * non-existing rule */
	ipset_envopt_parse(session, IPSET_ENV_EXIST, NULL);

	if (!has_ipset_setname(whitelist) &&
		!try_ipset_create(whitelist, TYPENAME)) {
		fprintf(stderr, "Failed to create %s: %s\n", whitelist,
				ipset_session_error(session));
		ipset_session_fini(session);
		return false;
	}
	if (!has_ipset_setname(blacklist) &&
		!try_ipset_create(blacklist, TYPENAME)) {
		fprintf(stderr, "Failed to create %s: %s\n", blacklist,
				ipset_session_error(session));
		ipset_session_fini(session);
		return false;
	}

	return true;
}

void blocker_fini(void) {
	ipset_session_fini(session);
}
