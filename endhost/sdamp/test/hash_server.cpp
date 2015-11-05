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

/*
void die(int signum)
{
    endwin();
    exit(0);
}
*/

int main()
{
    /*
    initscr();
    cbreak();
    noecho();

    signal(SIGINT, die);
    signal(SIGTERM, die);
    */

    SCIONSocket s(SCION_PROTO_SDAMP, NULL, 0, 8080, 0);
    SCIONSocket &newSocket = s.accept();
    printf("got new socket\n");
    //refresh();
    char buf[BUFSIZE];
    uint8_t recvdhash[20];
    memset(recvdhash, 0, 20);
    newSocket.recv((uint8_t *)recvdhash, 20, NULL);
    FILE *fp = fopen("recvdfile", "wb");
    int size = 0;
    struct timeval start, end;
    gettimeofday(&start, NULL);
    while (size < 1 * 1024 * 1024) {
        memset(buf, 0, BUFSIZE);
        int recvlen = newSocket.recv((uint8_t *)buf, BUFSIZE, NULL);
        gettimeofday(&end, NULL);
        fwrite(buf, 1, recvlen, fp);
        size += recvlen;

        /*
        SCIONStats stats;
        memset(&stats, 0, sizeof(stats));
        newSocket.getStats(&stats);
        clear();
        move(0, 0);
        printf("Current stats\n");
        for (int i = 0; i < MAX_TOTAL_PATHS; i++) {
            if (!(stats.exists[i]))
                continue;
            printf(">> Path %d <<\n", i);
            printf("Received: %d\n", stats.receivedPackets[i]);
            printf("Sent:     %d\n", stats.sentPackets[i]);
            printf("ACKed:    %d\n", stats.ackedPackets[i]);
            printf("RTT:      %d ms\n", stats.rtts[i] / 1000);
            printf("Loss:     %.2f\n", stats.lossRates[i]);
        }
        printf("\n");
        */

        long us = end.tv_usec - start.tv_usec + (end.tv_sec - start.tv_sec) * 1000000;
        printf("%d bytes: %f bps\n", size, (double)size / us * 1000000);
        //refresh();
    }
    printf("received total %d bytes\n", size);
    newSocket.send((uint8_t *)buf, BUFSIZE);
    //refresh();
    fclose(fp);

    CSHA1 sha;
    sha.HashFile("recvdfile");
    sha.Final();
    uint8_t hash[20];
    sha.GetHash(hash);

    bool success = true;
    //refresh();
    for (int i = 0; i < 20; i++) {
        if (hash[i] != recvdhash[i]) {
            printf("failed\n");
            //refresh();
            success = false;
            break;
        }
    }
    if (success) {
        printf("success\n");
        //refresh();
    }

    getch();
    endwin();

    exit(0);
}
