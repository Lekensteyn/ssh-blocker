#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdio.h>

/* L() = ensure length remaining
 * 1. L(); starts with "Invalid user " goto (1)
 * 2. L(); starts with "User " goto (2)
 *
 * (1)
 * 1. Length is at least "Invalid user  from 0.0.0.0"
 * 2. Length is at most "Invalid user (100) from 255.255.255"
 *
 * 4. Ends with " <IP>", skip
 * 5. Ends with " from"
 *
 * (2)
 * 1. Length is at least "User  from 0.0.0.0 not allowed because not listed in AllowUsers"
 * 2. Length is at most "User (100) from 255.255.255.255 not allowed because not listed in AllowUsers"
 * 3. Ends with " not allowed because not listed in AllowUsers", skip
 * 4. Ends with " <IP>", skip
 * 5. Ends with " from"
 */

#define IP_MINLENGTH (3 + 4 * 1)
#define IP_MAXLENGTH (3 + 4 * 3)
#define USER_MAXLENGTH 100

struct match_pattern {
	const char *start;
	size_t start_len;

	const char *end;
	size_t end_len;
};
#define PATTERN(start, end) { \
	start, \
	strlen(start), \
	end, \
	strlen(end) \
}

/**
 * Tries to locate an IP address at the end of the string.
 *
 * @param str String to search for an IP address.
 * @param len Length of the remaining string in bytes.
 * @param ip A matching IP address to store, must be at least INET_ADDRSTRLEN
 * bytes long.
 * @returns Length of matched IP address or 0 if there is no match.
 */
static size_t parse_ip(char *str, size_t len, char *ip) {
	char end;
	size_t ip_len = 0;
	struct in_addr addr;

	/* as long as the string can contain a non-space character */
	while (len - ip_len > 0 && str[len - ip_len - 1] != ' ')
		ip_len++;

	/* no space found */
	if (len == ip_len)
		return 0;

	/* save character after the IP address and terminate string there */
	end = str[len];
	str[len] = 0;

	/* test if it is a valid IPv4 address like 0.0.0.0 */
	if (inet_pton(AF_INET, str + len - ip_len, &addr) != 1 ||
		inet_ntop(AF_INET, &addr, ip, INET_ADDRSTRLEN) == NULL) {
		ip_len = 0;
	}

	/* restore string */
	str[len] = end;

	return ip_len;
}

static char * find_ip(char *str, struct match_pattern pattern, char *ip) {
	/* number of characters minus the discarded trailing chars */
	size_t len = strlen(str);
	const char *middle = " from";
	size_t middle_len = strlen(middle);
	size_t ip_len;

	/* ensure enough length */
	if (len < pattern.start_len + middle_len + 1 + IP_MINLENGTH + pattern.end_len)
		return NULL;

	/* ensure not too long */
	if (len > pattern.start_len + USER_MAXLENGTH + middle_len + 1 + IP_MAXLENGTH + pattern.end_len)
		return NULL;

	/* ensure string starts with pattern */
	if (memcmp(str, pattern.start, pattern.start_len) != 0)
		return NULL;

	/* ignore starting pattern */
	str += pattern.start_len;
	len -= pattern.start_len;

	if (pattern.end_len > 0) {
		/* ensure string ends with pattern, decreasing length */
		len -= pattern.end_len;
		if (memcmp(str + len, pattern.end, pattern.end_len) != 0)
			return NULL;
	}

	/* ip matching! */
	ip_len = parse_ip(str, len, ip);
	if (!ip_len)
		return NULL;

	/* ensure enough space for IP and middle part */
	if (len < middle_len + 1 + ip_len)
		return NULL;

	len -= middle_len + 1 + ip_len;

	/* ensure IP is preceded by the middle word */
	if (memcmp(str + len, middle, middle_len) != 0)
		return NULL;

	return ip;
}

int main(int argc, char **argv) {
	int i, patterns_count;
	char ip[INET_ADDRSTRLEN], *str;
	struct match_pattern patterns[] = {
		PATTERN("Invalid user ", ""),
		PATTERN("User ", " not allowed because not listed in AllowUsers"),
	};
	patterns_count = sizeof(patterns) / sizeof(*patterns);

	if (argc < 2) {
		fprintf(stderr, "Usage: foo\n");
		return 1;
	}

	str = argv[1];
	for (i = 0; i < patterns_count; i++) {
		if (find_ip(str, patterns[i], ip) != NULL) {
			printf("Found match: %s\n", ip);
		}
	}
	return 0;
}
