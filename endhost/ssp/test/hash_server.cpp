#include "SCIONSocket.h"
#include "SHA1.h"

#define BUFSIZE (1024 * 200)

int main()
{
    system("dd if=/dev/urandom of=randomfile bs=1024 count=1024");

    uint8_t hash[20];
    CSHA1 sha;
    sha.HashFile("randomfile");
    sha.Final();
    sha.GetHash(hash);

    printf("random data + hash ready\n");
    SCIONSocket s(SCION_PROTO_SSP, NULL, 0, 8080, 0);
    SCIONSocket *newSocket = s.accept();
    printf("got new socket\n");
    uint8_t buf[10];
    memset(buf, 0, 10);
    newSocket->recv(buf, 1, NULL);
    printf("read 1 byte\n");

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
