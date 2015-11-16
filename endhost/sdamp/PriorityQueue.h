#ifndef PRIORITY_QUEUE_H
#define PRIORITY_QUEUE_H

#include <algorithm>

#include "SCIONDefines.h"
#include "DataStructures.h"

typedef bool (*Compare)(void *, void *);

template <class T>
class PriorityQueue {
public:
    PriorityQueue(Compare c);

    size_t size();
    bool empty();
    T top();
    void push(T packet);
    void pop();
    typename std::vector<T>::iterator begin();
    typename std::vector<T>::iterator end();

private:
    Compare mComparator;
    std::vector<T> mVector;
};

#endif
