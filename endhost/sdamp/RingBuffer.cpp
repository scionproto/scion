#include "RingBuffer.h"

RingBuffer::RingBuffer(int size)
{
    mBuffer = (uint8_t *)malloc(size);
    mHead = 0;
    mTail = 0;
    mLen = size;
    mDirty = false;
}

RingBuffer::~RingBuffer()
{
    free(mBuffer);
}

int RingBuffer::write(uint8_t *buf, int len)
{
    if (!buf)
        return -1;
    if (len < 0)
        return -1;
    int available;
    if (mTail >= mHead)
        available = mLen - (mTail - mHead);
    else
        available = mHead - mTail;
    if (len > available)
        return -1;
    if (mTail + len > mLen) {
        int first = mLen - mTail;
        int second = len - first;
        memcpy(mBuffer + mTail, buf, first);
        memcpy(mBuffer, buf + first, second);
    } else {
        memcpy(mBuffer + mTail, buf, len);
    }
    mTail = (mTail + len) % mLen;
    if (!mDirty)
        mDirty = true;
    return len;
}

int RingBuffer::read(uint8_t *buf, int len)
{
    if (!buf)
        return -1;
    if (len < 0)
        return -1;
    if (!mDirty)
        return 0;
    int available;
    if (mTail == mHead)
        available = mDirty ? mLen : 0;
    else if (mTail > mHead)
        available = mTail - mHead;
    else
        available = mLen - (mHead - mTail);
    if (available == 0)
        return 0;
    int toRead = len < available ? len : available;
    if (mHead + toRead > mLen) {
        int first = mLen - mHead;
        int second = toRead - first;
        memcpy(buf, mBuffer + mHead, first);
        memcpy(buf + first, mBuffer, second);
    } else {
        memcpy(buf, mBuffer + mHead, toRead);
    }
    mHead = (mHead + toRead) % mLen;
    if (mHead == mTail)
        mDirty = false;
    return toRead;
}

void RingBuffer::get(int offset, int len, uint8_t *buf)
{
    if (offset + len >= mLen) {
        int first = mLen - offset;
        int second = len - first;
        memcpy(buf, mBuffer + offset, first);
        memcpy(buf, mBuffer, second);
    } else {
        memcpy(buf, mBuffer + offset, len);
    }
}

int RingBuffer::size()
{
    if (mTail == mHead)
        return mDirty ? mLen : 0;
    else if (mTail > mHead)
        return mTail - mHead;
    else
        return mLen - (mHead - mTail);
}

int RingBuffer::available()
{
    return mLen - this->size();
}

int RingBuffer::head()
{
    return mHead;
}

int RingBuffer::tail()
{
    return mTail;
}
