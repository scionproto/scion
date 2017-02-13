/* Copyright 2017 ETH Zürich
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * 	http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef UTIL_H_
#define UTIL_H_

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif


/* Reads any pending data in the socket and discards it.
 *
 * On success, the number of bytes discarded is returned. Otherwise a negative
 * system error number is returned.
 */
int clear_sock(int sockfd);


/* Blocks `timeout` milliseconds until data is available to be read then recvs
 * the data into the buffer.
 */
int poll_recv(int sockfd, uint8_t *buffer, size_t len, int timeout);


/* Creates a UNIX socket and connects to the specified unix address.
 *
 * On success, a sockfd file descriptor is returned. On error, a negative
 * system error code is returned, namely those relating to socket and connect.
 */
int unix_connect(const char* addr);


#ifdef __cplusplus
}
#endif

#endif /* ifndef UTIL_H_ */
