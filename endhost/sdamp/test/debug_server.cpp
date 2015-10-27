#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <ncurses.h>
#include <signal.h>
#include <Python.h>
#include "SCIONSocket.h"
#include "SHA1.h"

#define BUFSIZE 1024

int main()
{
    SCIONSocket s(SCION_PROTO_SDAMP, NULL, 0, 8080, 0);
    SCIONSocket &newSocket = s.accept();
    char buf[BUFSIZE];
    int size = 0;
    struct timeval start, end;
    gettimeofday(&start, NULL);
    while (1) {
        memset(buf, 0, BUFSIZE);
        int recvlen = newSocket.recv((uint8_t *)buf, BUFSIZE, NULL);
        gettimeofday(&end, NULL);
        size += recvlen;
        long us = end.tv_usec - start.tv_usec + (end.tv_sec - start.tv_sec) * 1000000;
        printf("%d bytes: %f bps\n", size, (double)size / us * 1000000);
    }
    exit(0);
}
