# pam_totp - GPLv2, Sascha Thomas Spreitzer, https://fedorahosted.org/pam_totp

libs		+= libcurl libconfig

CFLAGS		+= -std=c99 -fPIC -pthread $(shell pkg-config --cflags ${libs})

LDFLAGS		:= -shared -lpam -pthread $(shell pkg-config --libs ${libs})

arch		:= $(shell uname -m)
pamlib		:= lib/security

obj			:= pam_totp.so
objc		:= ${shell ls pam_totp*.c}
objo		:= ${objc:%.c=%.o}

# If platform is AMD/Intel 64bit
ifeq (${arch},x86_64)
pamlib := lib64/security
endif
ifeq (${arch},ppc64)
pamlib := lib64/security
endif

all: ${obj}

debug:
	CFLAGS="-g3 -O0" ${MAKE} all

${obj}: ${objo}
	${CC} ${LDFLAGS} -o ${obj} ${objo}

clean:
	rm -f ${obj} ${objo}

install:
	install -D -m 755 ${obj} ${DESTDIR}/${pamlib}/${obj}
	install -D -m 644 examples/pam_totp.conf ${DESTDIR}/etc/pam_totp.conf

uninstall:
	rm -f ${DESTDIR}/${pamlib}/${obj}
