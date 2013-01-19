/**
 * Read SSH log messages from a FIFO pipe and block IP addresses exceeding a
 * certain threshold by adding it with ipset.
 *
 * Copyright (C) 2013 Peter Wu <lekensteyn@gmail.com>
 * Licensed under GPLv3 or any latter version.
 *
 * Wishlist: capabilities should get support for inherited process capabilities.
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdbool.h>

/* size of the IP address list */
#define IPLIST_LENGTH 512

/* With this number of matches, an IP address will be blocked. range 1-254 */
#define MATCH_THRESHOLD 5

/* Type name, used when creating the set specified by SETNAME_BLACKLIST */
#define TYPENAME "hash:ip"

/* used for ipset and iptables match of ip addresses */
#define SETNAME_BLACKLIST "ssh-blocklist"

/* time before unblocking in seconds */
#define BLOCK_TIME 3600

void iplist_block(const struct in_addr addr);
void iplist_accept(const struct in_addr addr);

void do_block(const struct in_addr addr);
void do_unblock(const struct in_addr addr);
bool is_blocked(const struct in_addr addr);
void blocker_init(void);
void blocker_fini(void);
