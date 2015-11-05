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

#define BUFSIZE 1024

void die(int signum)
{
    endwin();
    exit(0);
}

int main()
{
    initscr();
    cbreak();
    noecho();

    signal(SIGINT, die);
    signal(SIGTERM, die);

    SCIONSocket s(SCION_PROTO_SDAMP, NULL, 0, 8080, 0);
    SCIONSocket &newSocket = s.accept();
    printw("got new socket\n");
    refresh();
    char buf[BUFSIZE];
    char recvdhash[129];
    memset(recvdhash, 0, 129);
    newSocket.recv((uint8_t *)recvdhash, 128, NULL);
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

        SCIONStats stats;
        memset(&stats, 0, sizeof(stats));
        newSocket.getStats(&stats);
        clear();
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

        long us = end.tv_usec - start.tv_usec + (end.tv_sec - start.tv_sec) * 1000000;
        printw("\n%d bytes: %f bps\n", size, (double)size / us * 1000000);
        refresh();
    }
    printw("received total %d bytes\n", size);
    refresh();
    fclose(fp);

    setenv("PYTHONPATH", "../../../lib/crypto", 0);

    PyObject *pmod, *pclass, *pargs, *pinst, *pmeth, *pres;

    Py_Initialize();
    pmod = PyImport_ImportModule("python_sha3");
    pclass = PyObject_GetAttrString(pmod, "Keccak");
    Py_DECREF(pmod);

    pargs = Py_BuildValue("(iii)", 1024, 576, 512);
    pinst = PyEval_CallObject(pclass, pargs);
    Py_DECREF(pclass);
    Py_DECREF(pargs);

    fp = fopen("randomfile", "rb");
    int len;
    while ((len = fread(buf, 1, 1024, fp)) > 0) {
        pmeth = PyObject_GetAttrString(pinst, "update");
        pargs = Py_BuildValue("(s#)", buf, len);
        PyEval_CallObject(pmeth, pargs);
        Py_DECREF(pargs);
        Py_DECREF(pmeth);
    }
    fclose(fp);

    pmeth = PyObject_GetAttrString(pinst, "hexdigest");
    pargs = Py_BuildValue("()");
    pres = PyEval_CallObject(pmeth, pargs);
    Py_DECREF(pargs);
    Py_DECREF(pmeth);
    Py_DECREF(pinst);

    char *hash;
    PyArg_Parse(pres, "y", &hash);

    printw("%s\n%s\n%s\n", recvdhash, hash, strcmp(recvdhash, hash) ? "fail" : "success");
    getch();
    endwin();

    exit(0);
}
