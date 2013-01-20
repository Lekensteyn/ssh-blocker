
SRC ?= ssh-blocker-pcre.c iplist.c ipset.c
OBJ ?= ssh-blocker
LIBS ?= -lpcre -lipset -lcap
CFLAGS ?= -O2 -g -D_FORTIFY_SOURCE=2 -pie -fPIE -Wl,-z,relro,-z,now

$(OBJ): $(SRC)
	scan-build --use-analyzer /usr/bin/clang \
		gcc $(CFLAGS) -Wall -Wextra -Wlogical-op -Wunused-macros \
		-Wstack-protector -fstack-protector -Wformat-security \
		$(SRC) -o $@ $(LIBS)
