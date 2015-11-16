#include "PriorityQueue.h"
#include "Utils.h"

using namespace std;

template <class T>
PriorityQueue<T>::PriorityQueue(Compare c)
{
    mComparator = c;
    mVector.clear();
    make_heap(mVector.begin(), mVector.end());
}

template <class T>
size_t PriorityQueue<T>::size()
{
    return mVector.size();
}

template <class T>
bool PriorityQueue<T>::empty()
{
    return mVector.empty();
}

template <class T>
T PriorityQueue<T>::top()
{
    return mVector.front();
}

template <class T>
void PriorityQueue<T>::push(T frame)
{
    mVector.push_back(frame);
    push_heap(mVector.begin(), mVector.end(), mComparator);
}

template <class T>
void PriorityQueue<T>::pop()
{
    pop_heap(mVector.begin(), mVector.end(), mComparator);
    mVector.pop_back();
}

template <class T>
typename vector<T>::iterator PriorityQueue<T>::begin()
{
    return mVector.begin();
}

template <class T>
typename vector<T>::iterator PriorityQueue<T>::end()
{
    return mVector.end();
}

template class PriorityQueue<SCIONPacket *>;
template class PriorityQueue<SDAMPFrame *>;
template class PriorityQueue<SSPInPacket *>;
