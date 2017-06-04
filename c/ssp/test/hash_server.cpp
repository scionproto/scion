#include "SCIONSocket.h"
#include "SHA1.h"

#define BUFSIZE (1024 * 200)

int main(int argc, char **argv)
{
    system("dd if=/dev/urandom of=randomfile bs=1024 count=1024");

    uint8_t hash[20];
    CSHA1 sha;
    sha.HashFile("randomfile");
    sha.Final();
    sha.GetHash(hash);
    printf("random data + hash ready\n");

    uint16_t isd;
    uint32_t as;
    char str[40];
    if (argc == 2) {
        isd = atoi(strtok(argv[1], "-"));
        as = atoi(strtok(NULL, "-"));
    } else {
        isd = 2;
        as = 26;
    }

    sprintf(str, "/run/shm/sciond/%d-%d.sock", isd, as);
    SCIONSocket s(L4_SSP, str);

    SCIONAddr addr;
    memset(&addr, 0, sizeof(addr));
    addr.host.port = 8080;
    s.bind(addr);
    s.listen();
    SCIONSocket *newSocket = s.accept();
    printf("got new socket\n");

    newSocket->send((uint8_t *)hash, 20);
    printf("hash sent: ");
    for (int i = 0; i < 20; i++)
        printf("%x", hash[i]);
    printf("\n");
    FILE *fp = fopen("randomfile", "rb");
    char fbuf[BUFSIZE];
    memset(fbuf, 0, BUFSIZE);
    int len = 0;
    while ((len = fread(fbuf, 1, BUFSIZE, fp)) > 0)
        newSocket->send((uint8_t *)fbuf, len);
    printf("done sending file\n");
    newSocket->shutdown();
    while (newSocket->recv((uint8_t *)fbuf, BUFSIZE, NULL) > 0);
    delete newSocket;
    fclose(fp);
    return 0;
}
