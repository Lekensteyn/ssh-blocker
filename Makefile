
SRC ?= ssh-blocker-pcre.c iplist.c ipset.c
OBJ ?= ssh-blocker-pcre
LIBS ?= -lpcre -lipset -lcap
CFLAGS ?= -O2 -g

$(OBJ): $(SRC)
	scan-build --use-analyzer /usr/bin/clang \
		gcc $(CFLAGS) -Wall -Wextra -Wlogical-op -Wunused-macros \
		-Wstack-protector -fstack-protector \
		$(SRC) -o $@ $(LIBS)
