CFLAGS= -Wall -fanalyzer -O2 -Warray-bounds -Wsequence-point -Walloc-zero -Wnull-dereference -Wpointer-arith -Wcast-qual -Wcast-align=strict
CPPFLAGS= -I../include
LDFLAGS= -lbfd

all: clang isos_inject clang_tidy asm

asm:
	nasm -f bin assembly.s

clang_tidy:
	clang-tidy --checks=cert-*,clang-analyzer--* isos_inject.c

clang:
	clang -fsyntax-only -Wall -Wextra -Wuninitialized -Wpointer-arith -Wcast-qual -Wcast-align -I ../include isos_inject.c
	clang -fsanitize=address -o sanitized_address -I ../include  isos_inject.c parser.c -lbfd
	clang -fsanitize=memory -o sanitized_memory  -I ../include  isos_inject.c parser.c -lbfd
	clang -fsanitize=undefined -o sanitized_undefined -I ../include  isos_inject.c parser.c -lbfd

isos_inject: isos_inject.o parser.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

isos_inject.o: isos_inject.c  ../include/parser.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c $<

parser.o: parser.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -c $<

clean: 
	rm -f isos_inject *.o sanitized_address sanitized_memory sanitized_undefined assembly
	cp ../backup/date_backup ./date

backup:
	@echo "Restoring the original date file..."
	cp ../backup/date_backup ./date

help:
	@echo "all compiling the software_security project with flags variable"
	@echo "backup restore the original executable"
	@echo "clean can remove temp files created during compilation"

.PHONY: all clean backup help 