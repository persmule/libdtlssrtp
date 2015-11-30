PCH = dtls_srtp.h
CFLAGS = -Wall -Wextra -fPIC -fpic -fpie -O3
LIBS = -lcrypto -lssl
TGLIB = libdtlssrtp.a
TEST = dtlssrtp_example

.PHONY: all test clean
all: $(TGLIB)

test: $(TEST)

$(TEST): example.o dsink_udp.o $(TGLIB)
	gcc -o $(TEST) $^ $(LIBS)

$(TGLIB): dtls_srtp.o
	ar cr $@ $^
	ranlib $@

%.o: %.c $(PCH).gch
	gcc $(CFLAGS) -c -o $@ $<

$(PCH).gch: $(PCH)
	gcc $(CFLAGS) -o $@ $<

clean:
	-rm *.o $(TGLIB) $(TEST)
