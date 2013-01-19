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

/* ipset whitelist of IP addresses */
#define SETNAME_WHITELIST "ssh-whitelist"

/* used for ipset and iptables match of ip addresses */
#define SETNAME_BLACKLIST "ssh-blocklist"

/* time to remember the last failed login attempt. If the elapsed time since an
 * entry was last updated is larger than this number of seconds, it will be
 * removed from the entries list */
#define REMEMBER_TIME 600

/* time before removing an IP from the whitelist. 0 means default (usually
 * infinity unless a "timeout" argument was specified when creating the list
 * with ipset) */
#define WHITELIST_TIME 3600

/* time before unblocking in seconds. See also WHITELIST_TIME */
#define BLOCK_TIME 3600

void iplist_block(const struct in_addr addr);
void iplist_accept(const struct in_addr addr);

void do_block(const struct in_addr addr);
void do_unblock(const struct in_addr addr);
void do_whitelist(const struct in_addr addr);
bool is_whitelisted(const struct in_addr addr);
void blocker_init(void);
void blocker_fini(void);
