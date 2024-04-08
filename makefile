LDLIBS= -lnetfilter_queue

all: nfqnl_test

nfqnl_test.o: nfqnl_test.c

nfqnl_test: nfqnl_test.o

clean:
	rm -f nfqnl_test 
	rm -f nfqnl_test.o