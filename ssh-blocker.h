/**
 * Read SSH log messages from a FIFO pipe and block IP addresses exceeding a
 * certain threshold by adding it with ipset.
 *
 * Copyright (C) 2013 Peter Wu <lekensteyn@gmail.com>
 * Licensed under GPLv3 or any latter version.
 *
 * Wishlist: capabilities should get support for inherited process capabilities.
 * Or a ipset library should become available.
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>

/* size of the IP address list */
#define IPLIST_LENGTH 512

/* With this number of matches, an IP address will be blocked. range 1-254 */
#define MATCH_THRESHOLD 5

#define IPSET_PROGRAM "/usr/sbin/ipset"
/* used for ipset and iptables match of ip addresses */
#define IPSET_SETNAME "ssh-blocklist"

void iplist_block(const struct in_addr addr);
void iplist_accept(const struct in_addr addr);

void iplist_whitelist_set(struct in_addr *addr, size_t addr_count);

void do_block(const struct in_addr addr);
void do_unblock(const struct in_addr addr);
