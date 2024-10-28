CC = cc
INCLUDEDIR = /usr/include
LIBDIR = /usr/lib
CFLAGS = -std=c99 -Wall -Wextra -Wimplicit-fallthrough -fPIC -O2 -g

HEADER = toml.h
SRC = toml.c
OBJ = ${SRC:.c=.o}
LIB = libtoml.a
SOLIB = libtoml.so

build: ${LIB} ${SOLIB}

${OBJ}: ${SRC} ${HEADER}
	${CC} ${CFLAGS} -c $<

${LIB}: ${OBJ}
	ar -rcs $@ $^

${SOLIB}: ${OBJ}
	${CC} ${CFLAGS} -shared -o $@ $^

install: ${LIB} ${SOLIB}
	install ${HEADER} ${DESTDIR}${INCLUDEDIR}
	install ${LIB} ${DESTDIR}${LIBDIR}
	install ${SOLIB} ${DESTDIR}${LIBDIR}
	rm -f *.o ${LIB} ${SOLIB}

uninstall:
	rm -rf ${DESTDIR}${INCLUDEDIR}/${HEADER} ${DESTDIR}${DESTDIR}${LIBDIR}/${LIB} ${DESTDIR}${DESTDIR}${LIBDIR}/${SOLIB}

clean:
	rm -f *.o ${LIB} ${SOLIB}

.PHONY: build install

