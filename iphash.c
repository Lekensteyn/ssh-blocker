/**
 * Manage a set of IP addresses, blocking them if certain limits are reached.
 *
 * Copyright (C) 2013 Peter Wu <lekensteyn@gmail.com>
 * Licensed under GPLv3 or any latter version.
 */

#include "ssh-blocker.h"
#include <time.h>
#include <search.h>

#define IP_STR_SIZE 6

#undef IP6_DATASTRUCTS

#ifndef IP6_DATASTRUCTS
/* general storage type for an IP address */
typedef struct in_addr addr_type;
#else
#	error IPv6 data structures not fully implemented yet
#endif

#define ADDR_SET(dst, src) ((dst).s_addr = (src).s_addr)

typedef struct {
	addr_type addr;
	unsigned char matches;
	time_t last_match;
#if 0
	some_time_type_here ...;
	struct ip_entry *prev;
	struct ip_entry *next;
#endif
} ip_entry;

/**
 * convert 32-bit ip address into a zero-terminated string
 * represenation
 */
char *ip2str(unsigned long const ip, char *str) {
				char *ipc  = (char *) &ip;
	unsigned long *strl = (unsigned long *) str;
#if 0
	str[0] = 1 | ipc[0];
	str[1] = 1 | ipc[1];
	str[2] = 1 | ipc[2];
	str[3] = 1 | ipc[3];
#else // optimization
	*strl = 0x01010101 | ip;
#endif
	str[4] = 1 | ((ipc[0] & 0x01) << 1)
				  | ((ipc[1] & 0x01) << 2)
				  | ((ipc[2] & 0x01) << 3)
				  | ((ipc[3] & 0x01) << 4);
	str[5] = 0;
	return str;
}

/**
 * convert the zero-terminated string representation of an ip
 * into a 32-bit representation
 * represenation
 */
unsigned long str2ip(char const *str, unsigned long *ip) {
	unsigned long *strl = (unsigned long *) str;
#if 0
				char *ipc  = (char *) ip;
	ipc[0] = str[0] & (0xFE | ((str[4] >> 1) & 0x01));
	ipc[1] = str[1] & (0xFE | ((str[4] >> 2) & 0x01));
	ipc[2] = str[2] & (0xFE | ((str[4] >> 3) & 0x01));
	ipc[3] = str[3] & (0xFE | ((str[4] >> 4) & 0x01));
#else // optimization
	*ip = *strl & (0xFEFEFEFE | ((str[4] & 0x02) >> 1)
									  | ((str[4] & 0x04) << 6)
									  | ((str[4] & 0x08) << (5 + 8))
									  | ((str[4] & 0x10) << (4 + 8 + 8)));
#endif
	return *ip;
}

void iphash_block(const struct in_addr addr) {
	time_t now;

	if (is_whitelisted(addr))
		return;

	now = time(NULL);

	ENTRY hentry, *hentryp;

	hentry.key = malloc(IP_STR_SIZE);
	if (hentry.key == NULL) return;

	ip2str(addr.s_addr, hentry.key);

	hentry.data = NULL;

	hentryp = hsearch(hentry, ENTER);

	if (hentryp == NULL) {
		fprintf(stderr, "Hash table full\n");
		return;
	}

	if (hentryp->data == NULL) { /* IP wasn't entered before */
		hentryp->data = malloc(sizeof(ip_entry));
		if (hentryp->data == NULL) return;
		ADDR_SET(((ip_entry *) hentryp->data)->addr, addr);
		((ip_entry *) hentryp->data)->matches = 0;
	} else { /* IP was entered before */
		free(hentry.key);
		if (now - ((ip_entry *) hentryp->data)->last_match > REMEMBER_TIME) {
			((ip_entry *) hentryp->data)->matches = 0;
		}
	}

	/* Do not re-block when threshold is reached already */
	if (((ip_entry *) hentryp->data)->matches <= MATCH_THRESHOLD) {

		++(((ip_entry *) hentryp->data)->matches);

		((ip_entry *) hentryp->data)->last_match = now;

		if (((ip_entry *) hentryp->data)->matches >= MATCH_THRESHOLD) {
			fprintf(stderr, "IP %s blocked.\n", inet_ntoa(addr));
			do_block(addr);
		}
	}
}

/* forget an IP when a succesful login is detected */
void iphash_accept(const struct in_addr addr) {
	char ip_str[IP_STR_SIZE];

	if (is_whitelisted(addr))
		return;

	ENTRY hentry, *hentryp;
	hentry.key = ip_str;
	ip2str(addr.s_addr, ip_str);
	if ((hentryp = hsearch(hentry, FIND)) != NULL) {
		/* remove addr from block list */
		if (((ip_entry *) hentryp->data)->matches >= MATCH_THRESHOLD)
			do_unblock(addr);

		free(hentryp->data);
		hentryp->data = NULL;
	}
	do_whitelist(addr);
}
