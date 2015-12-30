PCH = dtls_srtp.h
RANLIB = ranlib
CFLAGS = -Wall -Wextra -fPIC -fpic -O3
INCLUDE =
SYSROOT =
LIBPATH =
LIBS = -lcrypto -lssl
TGLIB = libdtlssrtp.a
TEST = dtlssrtp_example

.PHONY: all test clean
all: $(TGLIB)

test: $(TEST)

$(TEST): example.o dsink_udp.o $(TGLIB)
	$(CC) -o $(TEST) $^ $(LIBPATH) $(LIBS)

$(TGLIB): dtls_srtp.o
	$(AR) cr $@ $^
	$(RANLIB) $@

%.o: %.c $(PCH).gch
	$(CC) $(CFLAGS) $(INCLUDE) $(SYSROOT) -c -o $@ $<

$(PCH).gch: $(PCH)
	$(CC) $(CFLAGS) $(INCLUDE) $(SYSROOT) -o $@ $<

clean:
	-rm *.o $(TGLIB) $(TEST)
