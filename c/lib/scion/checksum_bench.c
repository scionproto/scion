#include <inttypes.h>
#include <signal.h>
#include <stdio.h>
#include <unistd.h>
#include "scion.h"

#define RUN_TIME 15

uint8_t data[4096];

void set_alarm();
void alarm_handler(int sig);
void simple_test();
void complex_test();

static int running;

int main() {
    simple_test();
    complex_test();
    return 0;
}

void set_alarm() {
    running = 1;
    signal(SIGALRM, alarm_handler);
    alarm(RUN_TIME);
}

void alarm_handler(int sig) {
    running = 0;
}

void simple_test() {
    uint64_t i;
    chk_input *input = mk_chk_input(1);
    set_alarm();
    for (i = 0; running; i++) {
        input->idx = 0;
        chk_add_chunk(input, data, sizeof(data));
        checksum(input);
    }
    printf("simple_test(%zu = %zuB): %" PRIu64 " in %ds (%.2lfM calls/s)\n",
        sizeof(data), sizeof(data), i, RUN_TIME, ((double)i/RUN_TIME)/1000000);
}

void complex_test() {
    uint64_t i;
    chk_input *input = mk_chk_input(5);
    set_alarm();
    for (i = 0; running; i++) {
        input->idx = 0;
        chk_add_chunk(input, &data[0], 8);
        chk_add_chunk(input, &data[8], 8);
        chk_add_chunk(input, &data[16], 2);
        chk_add_chunk(input, &data[18], 12);
        chk_add_chunk(input, &data[30], 1391);
        checksum(input);
    }
    printf("complex_test(8+8+2+12+1391 = 1421B): %" PRIu64 " in %" PRId32 "s (%.2lfM calls/s)\n",
            i, RUN_TIME, ((double)i/RUN_TIME)/1000000);
}
