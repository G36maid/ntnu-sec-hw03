
TARGET = retlib
PRTENV = prtenv

all: ${TARGET} ${PRTENV}

N = 12

retlib: retlib.c
	gcc -m32 -DBUF_SIZE=${N} -fno-stack-protector -z noexecstack -o $@ $@.c
	sudo chown root $@ && sudo chmod 4755 $@

prtenv: prtenv.c
	gcc -m32 -fno-stack-protector -z noexecstack -o $@ $@.c

clean:
	rm -f *.o *.out ${TARGET} ${PRTENV} badfile
