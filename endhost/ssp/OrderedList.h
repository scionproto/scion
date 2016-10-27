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
