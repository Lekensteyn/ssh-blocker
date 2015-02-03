/**
 * Read SSH log messages from a FIFO pipe and block IP addresses exceeding a
 * certain threshold by adding it with ipset.
 *
 * Copyright (C) 2013 Peter Wu <lekensteyn@gmail.com>
 * Licensed under GPLv3 or any latter version.
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdbool.h>
#include <pcre.h>

/* size of the IP address list */
#define IPHASH_LENGTH 512

/* With this number of matches, an IP address will be blocked. range 1-254 */
#define MATCH_THRESHOLD 2

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
#define WHITELIST_TIME 3600 * 24

/* time before unblocking in seconds. See also WHITELIST_TIME */
#define BLOCK_TIME 3600

#define USER "(?:[a-z_][a-z0-9_-]*[$]?)"
#define IP_ELEMENT "(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])"
#define IP IP_ELEMENT "\\." IP_ELEMENT "\\." IP_ELEMENT "\\." IP_ELEMENT
#define WIP "(?<wip>" IP ")"
#define BIP "(?<bip>" IP ")"

#define SSH_PATTERN \
   "Invalid user " USER " from " BIP "$" "|" \
   "User " USER " from " BIP " not allowed because not listed in AllowUsers$" "|" \
   "Accepted publickey for " USER " from " WIP " port [0-9]{1,5} ssh2$"

/* global variables */
unsigned int  remember;
unsigned int  threshold;
char         *whitelist;
char         *blacklist;
unsigned int  whitetime;
unsigned int  blacktime;

int log_open(uid_t uid, const char *filename);
int log_read_line(char *buf, size_t buf_size);
void log_close(void);

struct log_pattern {
	const char *regex;
	pcre *pattern;
	bool is_whitelist;
};
pcre *pattern_compile(const char *pattern);
void pattern_fini(pcre **pattern);
/* maximum number of groups in regex */
#define REGEX_MAX_GROUPS 3

void iphash_block(const struct in_addr addr);
void iphash_accept(const struct in_addr addr);

void do_block(const struct in_addr addr);
void do_unblock(const struct in_addr addr);
void do_whitelist(const struct in_addr addr);
bool is_whitelisted(const struct in_addr addr);
bool blocker_init(void);
void blocker_fini(void);
