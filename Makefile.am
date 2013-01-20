dist_doc_DATA = README

AM_CFLAGS = -O2 -g -D_FORTIFY_SOURCE=2 -pie -fPIE -fstack-protector-all \
		-Wall -Wextra -Wlogical-op -Wunused-macros -Wstack-protector -Wformat-security\
		$(pcre_CFLAGS) $(ipset_CFLAGS)
AM_LDFLAGS = -z relro -z now

sbin_PROGRAMS = ssh-blocker
ssh_blocker_SOURCES = ssh-blocker-pcre.c iplist.c ipset.c regex.c ssh-blocker.h
ssh_blocker_LDADD = $(pcre_LIBS) $(ipset_LIBS)
