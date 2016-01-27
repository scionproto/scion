#ifndef ORDERED_LIST_H
#define ORDERED_LIST_H

#include <list>

#include "DataStructures.h"
#include "SCIONDefines.h"

using namespace std;

typedef int (*Compare)(void *, void *);
typedef void (*Destroy)(void *);

template <class T>
class OrderedList {
public:
    OrderedList(Compare c, Destroy d);

    size_t size();
    bool empty();
    T front();
    bool push(T val);
    T pop();
    typename list<T>::iterator begin();
    typename list<T>::iterator end();
    typename list<T>::iterator erase(typename list<T>::iterator pos);
    void clean();

private:
    Compare mComparator;
    Destroy mDestroy;
    list<T> mList;
};

#endif
