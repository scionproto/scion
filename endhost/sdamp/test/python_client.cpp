#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdio.h>
#include <ncurses.h>
#include <signal.h>
#include <Python.h>
#include "SCIONSocket.h"

#define BUFSIZE 10240

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

    FILE *fp = fopen("randomfile", "rb");
    char fbuf[BUFSIZE];
    int len, total = 0;
    while ((len = fread(fbuf, 1, BUFSIZE, fp)) > 0) {
        total += len;
        refresh();
        pmeth = PyObject_GetAttrString(pinst, "update");
        pargs = Py_BuildValue("(s#)", fbuf, len);
        PyEval_CallObject(pmeth, pargs);
        Py_DECREF(pargs);
        Py_DECREF(pmeth);
        move(0, 0);
        printw("read %d bytes of file, total = %d\n", len, total);
        refresh();
    }
    fclose(fp);
    printw("done reading file for digest\n");
    refresh();

    pmeth = PyObject_GetAttrString(pinst, "hexdigest");
    pargs = Py_BuildValue("()");
    pres = PyEval_CallObject(pmeth, pargs);
    Py_DECREF(pargs);
    Py_DECREF(pmeth);
    Py_DECREF(pinst);

    char *hash;
    PyArg_Parse(pres, "y", &hash);
    printw("hash: %s\n", hash);
    printw("length: %d\n", strlen(hash));
    refresh();

    SCIONAddr *addrs[1];
    SCIONAddr saddr;
    saddr.ISD_AD(1, 5);
    saddr.host.addrLen = 4;
    in_addr_t in = inet_addr("192.33.93.195");
    memcpy(saddr.host.addr, &in, 4);
    addrs[0] = &saddr;
    SCIONSocket s(SCION_PROTO_SDAMP, addrs, 1, 0, 8080);
    s.send((uint8_t *)hash, 128);
    Py_DECREF(pres);
    printw("hash sent\n");
    refresh();
    fp = fopen("randomfile", "rb");
    while ((len = fread(fbuf, 1, 1024, fp)) > 0) {
        s.send((uint8_t *)fbuf, len);

        SCIONStats stats;
        memset(&stats, 0, sizeof(stats));
        s.getStats(&stats);
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
        refresh();
    }
    printw("done sending file\n");
    refresh();
    fclose(fp);
    getch();
    endwin();
    exit(0);
}
