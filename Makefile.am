dist_doc_DATA = README

AM_CFLAGS = -O2 -g -D_FORTIFY_SOURCE=2 -pie -fPIE -fstack-protector-all \
		-Wall -Wextra -Wlogical-op -Wunused-macros -Wstack-protector -Wformat-security\
		$(pcre_CFLAGS) $(ipset_CFLAGS)
AM_LDFLAGS = -z relro -z now

sbin_PROGRAMS = ssh-blocker
ssh_blocker_SOURCES = ssh-blocker-pcre.c iplist.c ipset.c regex.c ssh-blocker.h
ssh_blocker_LDADD = $(pcre_LIBS) $(ipset_LIBS)

do_subst = $(SED) 's|[@]sbindir[@]|@sbindir@|g' $< > $@

systemd/ssh-blocker.service: systemd/ssh-blocker.service.in
	$(do_subst)

EXTRA_DIST = \
	systemd/ssh-blocker.service.in \
	debian/ssh-blocker.init

if HAVE_SYSTEMD
AM_CFLAGS += $(systemd_CFLAGS)
ssh_blocker_SOURCES += log-systemd.c
ssh_blocker_LDADD += $(systemd_LIBS)

systemddir = $(SYSTEMD_UNITDIR)
systemd_DATA = systemd/ssh-blocker.service
CLEANFILES = systemd/ssh-blocker.service
else
ssh_blocker_SOURCES += log-pipe.c
endif
