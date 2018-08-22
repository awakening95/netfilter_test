all : nfqnl_test

nfqnl_test: main.o
	gcc -o nfqnl_test main.o -lnetfilter_queue

main.o: main.c
	gcc -c -o main.o main.c -lnetfilter_queue

clean:
	rm -f nfqnl_test
	rm -f *.o

