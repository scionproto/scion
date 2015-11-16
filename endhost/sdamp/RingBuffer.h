#ifndef RING_BUFFER_H
#define RING_BUFFER_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

class RingBuffer
{
public:
    RingBuffer(int size);
    ~RingBuffer();
    int write(uint8_t *buf, int len);
    int read(uint8_t *buf, int len);
    void get(int offset, int len, uint8_t *buf);
    int size();
    int available();
    int head();
    int tail();

private:
    uint8_t *mBuffer;
    int mHead;
    int mTail;
    int mLen;
    bool mDirty;
};

#endif
