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

/* This file contains functions and types useful for interfacing with the
 * SCION daemon service.
 */

#ifndef SCIONDLIB_H_
#define SCIONDLIB_H_


#include <stdint.h>

#include "packet.h"


#ifdef __cplusplus
extern "C" {
#endif


/*
 * An interface traversed by a SCION path as seen from within the specified AS.
 */
typedef struct {
  uint32_t isd_as;  // The ISD & AS identifer for the AS
  uint16_t link;    // The identifier of the link traversed
} sinterface_t;


/*
 * A path record returned from a SCION daemon query.
 */
typedef struct {
  spath_t path;             // Forwarding path data
  uint16_t mtu;             // Path MTU
  uint8_t interface_count;  // The number of interfaces traversed
  sinterface_t* interfaces;
} spath_record_t;


/*
 * Returns 1 (true) if the two paths in the two records use the same
 * interfaces, 0 (false) otherwise.
 */
int has_same_interfaces(const spath_record_t* record_a,
                        const spath_record_t* record_b);


/* Creates a socket and connects to the SCION daemon specified by daemon_addr.
 *
 * On success, a sockfd file descriptor is returned. On error, a negative
 * system error code is returned, namely those relating to socket and connect.
 *
 * @param daemon_addr The AF_UNIX address of the SCION daemon.
 */
int daemon_connect(const char* daemon_addr);


/* Writes the SCION daemon request for paths to the AS specified to the buffer.
 * The buffer should have at least DP_HEADER_LEN + 5 bytes of space.
 *
 * Returns the number of bytes written to the buffer.
 */
int write_path_request(uint8_t* buffer, uint32_t isd_as);


/* Parse network byte-order host address and populate the supplied addr with
 * a copy of the data.
 *
 * On success, returns the number of bytes used for the host address. If the
 * remaining input in the buffer, as indicated by data_len, is less than the
 * needed data, zero is returned.
 */
int parse_host_addr(uint8_t* buffer, int data_len, HostAddr* host_addr);


/* Parse a SCION path consisting of the raw path data and first hop address.
 *
 * On success, returns the number of bytes used in parsing. If the size of
 * data_len indicates insufficent data, zero is returned.
 */
int parse_path(uint8_t* buffer, int data_len, spath_t* path_ptr);


/* Parses the buffer and populates the path record with the availale data. The
 * buffer should be in network byte-order and data_len should indicate
 * suffient data in the buffer for the parsing.
 *
 * On success, returns the number of bytes used in parsing. If the size of
 * data_len indicates insufficent data, zero is returned.
 */
int parse_path_record(uint8_t* buffer, int data_len, spath_record_t* record);


/* De-initializes the specified path, freeing any internally allocated memory.
 * The memory pointed to by the record itself is not freed however.
 */
void destroy_spath(spath_t* path);


#ifdef __cplusplus
}
#endif

#endif /* ifndef SCIONDLIB_H_ */
