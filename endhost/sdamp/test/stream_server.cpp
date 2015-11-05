#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <ncurses.h>
#include <signal.h>
#include "SCIONSocket.h"

#define BUFSIZE 256

void die(int signum)
{
    endwin();
    exit(0);
}

int main()
{
    initscr();
    cbreak();

    signal(SIGINT, die);
    signal(SIGTERM, die);

    SCIONSocket s(SCION_PROTO_SDAMP, NULL, 0, 8080, 0);
    SCIONSocket &newSocket = s.accept();
    printw("got new socket\n");
    refresh();
    char buf[BUFSIZE];
    int total = 0;
    struct timeval start, end;
    gettimeofday(&start, NULL);
    while (1) {
        memset(buf, 0, BUFSIZE);
        int len = newSocket.recv((uint8_t *)buf, BUFSIZE, NULL);
        total += len;
        gettimeofday(&end, NULL);
        long us = end.tv_usec - start.tv_usec + (end.tv_sec - start.tv_sec) * 1000000;
        double rate = (double)total / us * 1000000;

        SCIONStats stats;
        memset(&stats, 0, sizeof(stats));
        newSocket.getStats(&stats);
        //clear();
        move(0, 0);
        printw("Current stats\n");
        for (int i = 0; i < MAX_TOTAL_PATHS; i++) {
            if (!(stats.exists[i]))
                continue;
            printw(">> Path %d <<\n", i);
            printw("Received: %d\n", stats.receivedPackets[i]);
            printw("Sent:     %d\n", stats.sentPackets[i]);
            printw("ACKed:    %d\n", stats.ackedPackets[i]);
            printw("RTT:      %d ms\n", stats.rtts[i] / 1000);
            printw("Loss:     %.2f\n", stats.lossRates[i]);
        }
        printw("\n");

        printw("\n%d bytes: %f bps\n", total, rate);
        refresh();
    }
    return 0;
}
