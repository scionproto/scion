#include <curl/curl.h>

#include "SCIONSocket.h"

#define BUFSIZE 1024
#define PATHS 3

size_t dummy(void *buffer, size_t size, size_t nmemb, void *userp)
{
    return size * nmemb;
}

int main()
{
    SCIONSocket s(SCION_PROTO_SSP, NULL, 0, 8080, 0);
    SCIONSocket *newSocket = s.accept();
    char buf[BUFSIZE];
    char curldata[1024];
    int size = 0;
    int count = 0;
    struct timeval start, end, period;
    gettimeofday(&start, NULL);
    period = start;
    CURL *curl;
    curl_global_init(CURL_GLOBAL_ALL);
    curl = curl_easy_init();
    if (!curl) {
        printf("curl init failed\n");
        return 1;
    }
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, dummy);
    struct curl_slist *headers = NULL;
    //headers = curl_slist_append(headers, "Accept: application/json");
    headers = curl_slist_append(headers, "Content-Type: application/json");
    //headers = curl_slist_append(headers, "charsets: utf-8");
    //headers = curl_slist_append(headers, "dataType: json");
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_URL, "http://192.33.93.167:8000/setup");
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS,
            "{\r\n"
            "\t\"source\": \"1-17\",\r\n"
            "\t\"destination\": \"2-26\",\r\n"
            "\t\"path1\": [\"1-17\", \"1-14\", \"1-11\", \"2-21\", \"2-23\", \"2-26\"],\r\n"
            "\t\"path2\": [\"1-17\", \"1-14\", \"1-11\", \"1-12\", \"2-22\", \"2-24\", \"2-26\"],\r\n"
            "\t\"path3\": [\"1-17\", \"1-14\", \"2-23\", \"2-26\"]\r\n"
            "}");
    curl_easy_perform(curl);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS,
            "{\r\n"
            "\t\"source\": \"none\",\r\n"
            "\t\"destination\": \"none\",\r\n"
            "\t\"path1\": \"red\",\r\n"
            "\t\"path2\": \"green\",\r\n"
            "\t\"path3\": \"yellow\"\r\n"
            "}");
    curl_easy_setopt(curl, CURLOPT_URL, "http://192.33.93.167:8000/color");
    curl_easy_perform(curl);
    while (1) {
        memset(buf, 0, BUFSIZE);
        int recvlen = newSocket->recv((uint8_t *)buf, BUFSIZE, NULL);
        gettimeofday(&end, NULL);
        size += recvlen;
        long us = end.tv_usec - period.tv_usec + (end.tv_sec - period.tv_sec) * 1000000;
        if (us > 1000000) {
            count++;
            SCIONStats *stats;
            stats = newSocket->getStats();
            printf("%d bytes: %f Mbps\n", size, (double)size / us * 1000000 / 1024 / 1024 * 8);
            sprintf(curldata, "{\
                    \"throughput\":{\"black\": [{\"time\":%d,\"value\":%.2f}]}\
                    }",
                    count, (double)size / us * 1000000 / 1024 / 1024 * 8);
            curl_easy_setopt(curl, CURLOPT_URL, "http://192.33.93.167:8000/metrics");
            curl_easy_setopt(curl, CURLOPT_POSTFIELDS, curldata);
            curl_easy_perform(curl);
            period = end;
            size = 0;
            destroyStats(stats);
        }
    }
    exit(0);
}
