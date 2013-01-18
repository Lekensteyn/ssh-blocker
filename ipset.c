#include "ssh-blocker.h"
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

static void ipset_run(char *action, char *ip) {
	char *cmd[] = {
		IPSET_PROGRAM,
		action,
		IPSET_SETNAME,
		ip,
		NULL
	};
	pid_t child;
	child = fork();
	if (child < 0) {
		perror("fork");
	} else if (child == 0) {
		execv(IPSET_PROGRAM, cmd);
		perror("execv");
	} else { /* child > 0 aka parent */
		waitpid(child, NULL, 0);
	}
}

#define IP_STR(addr) \
	char ip[INET_ADDRSTRLEN]; \
	inet_ntop(AF_INET, addr, ip, sizeof ip);

void do_block(const struct in_addr addr) {
	IP_STR(&addr);
	ipset_run("-A", ip);
}

void do_unblock(const struct in_addr addr) {
	IP_STR(&addr);
	ipset_run("-D", ip);
}
