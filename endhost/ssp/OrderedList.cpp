/* Copyright 2015 ETH Zurich
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "OrderedList.h"
#include "Utils.h"

using namespace std;

template <class T>
OrderedList<T>::OrderedList(Compare c, Destroy d)
{
    mComparator = c;
    mDestroy = d;
    mList.clear();
}

template <class T>
size_t OrderedList<T>::size()
{
    return mList.size();
}

template <class T>
bool OrderedList<T>::empty()
{
    return mList.empty();
}

template <class T>
T OrderedList<T>::front()
{
    return mList.front();
}

template <class T>
bool OrderedList<T>::push(T val)
{
    if (mComparator == NULL) {
        mList.push_back(val);
        return false;
    }

    typename list<T>::iterator i;
    for (i = mList.begin(); i != mList.end(); i++) {
        if (mComparator(val, *i) < 0) {
            mList.insert(i, val);
            return false;
        } else if (mComparator(val, *i) == 0) {
            return true;
        }
    }
    mList.push_back(val);
    return false;
}

template <class T>
T OrderedList<T>::pop()
{
    T front = mList.front();
    mList.pop_front();
    return front;
}

template <class T>
typename list<T>::iterator OrderedList<T>::begin()
{
    return mList.begin();
}

template <class T>
typename list<T>::iterator OrderedList<T>::end()
{
    return mList.end();
}

template <class T>
typename list<T>::iterator OrderedList<T>::erase(typename list<T>::iterator pos)
{
    return mList.erase(pos);
}

template <class T>
void OrderedList<T>::clean()
{
    typename list<T>::iterator i;
    for (i = mList.begin(); i != mList.end(); i++)
        mDestroy(*i);
}

template class OrderedList<SCIONPacket *>;
template class OrderedList<SSPPacket *>;
