#include "ssh-blocker.h"
#include <stdbool.h>

#undef IP6_DATASTRUCTS

#ifndef IP6_DATASTRUCTS
/* general storage type for an IP address */
typedef struct in_addr addr_type;
/* returns a 32-bit integer hash of the address */
#define IPHASH32(addr) ((addr).s_addr)
#else
#	error IPv6 data structures not fully implemented yet
#endif

#define ADDR_EQUALS(a, b) (IPHASH32(a) == IPHASH32(b))
#define ADDR_SET(dst, src) ((dst).s_addr = (src).s_addr)

typedef struct {
	addr_type addr;
	unsigned char matches;
#if 0
	some_time_type_here ...;
	struct ip_entry *prev;
	struct ip_entry *next;
#endif
} ip_entry;

static addr_type *whitelist = NULL;
static size_t whitelist_len;
static ip_entry entries[IPLIST_LENGTH];
static size_t pos = 0;

static ip_entry *find(addr_type addr) {
	unsigned int i;

	for (i = 0; i < IPLIST_LENGTH; i++) {
		if (ADDR_EQUALS(entries[i].addr, addr)) {
			return &entries[i];
		}
	}

	return NULL;
}

static ip_entry *next_available(void) {
	ip_entry *entry;

	pos = (pos + 1) % IPLIST_LENGTH;
	entry = &entries[pos];

	/* release old block */
	if (entry->matches >= MATCH_THRESHOLD)
		do_unblock(entry->addr);

	return entry;
}

static int whitelist_cmp(const void *a, const void *b) {
	return ADDR_EQUALS(*(addr_type *) a, *(addr_type *) b);
}

static bool is_whitelisted(addr_type addr) {
	if (whitelist == NULL)
		return false;

	return bsearch(&addr, whitelist, whitelist_len, sizeof(*whitelist), whitelist_cmp) != NULL;
}

void iplist_block(const struct in_addr addr) {
	ip_entry *entry;

	if (is_whitelisted(addr))
		return;

	entry = find(addr);
	if (!entry) {
		entry = next_available();
		ADDR_SET(entry->addr, addr);
		entry->matches = 0;
	}

	/* Do not re-block when threshold is reached already */
	if (entry->matches <= MATCH_THRESHOLD) {
		++entry->matches;

		if (entry->matches >= MATCH_THRESHOLD)
			do_block(addr);
	}
}

/* forget an IP when a succesful login is detected */
void iplist_accept(const struct in_addr addr) {
	ip_entry *entry = find(addr);

	if (is_whitelisted(addr))
		return;

	if (entry) {
		if (entry->matches >= MATCH_THRESHOLD)
			do_unblock(addr);

		memset(entry, 0, sizeof(*entry));
	}
}

void iplist_whitelist_set(struct in_addr *addrs, size_t addr_count) {
	whitelist_len = addr_count;
	whitelist = addrs;
	if (addr_count)
		qsort(whitelist, whitelist_len, sizeof(*whitelist), whitelist_cmp);
}
