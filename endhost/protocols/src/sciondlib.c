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


#include <errno.h>
#include <assert.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/un.h>
#include <sys/types.h>
#include <sys/socket.h>

#include "sciondlib.h"
#include "util.h"
#include "utils.h"
#include "defines.h"


int daemon_connect(const char* daemon_addr)
{
  // Create a unix socket
  int sockfd = socket(AF_UNIX, SOCK_STREAM, 0);
  if (sockfd == -1) {
    return -errno;
  }

  // Define the UNIX address
  struct sockaddr_un sock_addr;
  sock_addr.sun_family = AF_UNIX;
  strncpy(sock_addr.sun_path, daemon_addr, sizeof(sock_addr.sun_path));
  // Null the final byte of the sun_path, in case the address was too long.
  sock_addr.sun_path[sizeof(sock_addr.sun_path)-1] = '\0';

  // Connect to the daemon
  if(connect(sockfd, (struct sockaddr*)(&sock_addr), sizeof(sock_addr)) == -1) {
    // Store the errno as close may overwrite it
    int connect_error = errno;
    // Cleanup the socket file descriptor
    assert(close(sockfd) == 0);
    return -connect_error;
  } else {
    return sockfd;
  }
}


int write_path_request(uint8_t *buffer, uint32_t isd_as)
{
  int offset = 0;
  // Write the dispatcher header
  write_dp_header(buffer, /*host=*/NULL, /*packet_len=*/5);
  offset += DP_HEADER_LEN;

  // Write the opcode and ISD_AS address [ 0x00 || isd_as ]
  buffer[offset] = 0x00;
  isd_as = htonl(isd_as);  // Convert the destination to network byte order
  memcpy(&buffer[offset+1], &isd_as, sizeof(isd_as));
  offset += (1 + sizeof(isd_as));

  return offset;
}

// typedef struct {
//     uint8_t len;
//     uint8_t *raw_path;
//     HostAddr first_hop;
// } spath_t;


/* Parse network byte-order host address and populate the supplied addr with
 * a copy of the data.
 *
 * Returns the number of bytes which contains the host address in the buffer.
 */
int parse_host_addr(uint8_t* buffer, HostAddr* host_addr)
{
  int offset = 0;

  // Get the address type
  host_addr->addr_type = buffer[offset++];

  // Copy the address data
  memcpy(host_addr->addr, &buffer[offset], get_addr_len(host_addr->addr_type));
  offset += get_addr_len(host_addr->addr_type);

  // Copy the 2-byte port and change its edianness
  host_addr->port = ntohs((buffer[offset] << 8) | buffer[offset+1]);
  offset += 2;

  return offset;
}


// TODO(jsmith): Is all allocated memory freed in case of failure?
// TODO(jsmith): Function to appropriately free the paths
// TODO(jsmith): Assume that the fucntion to deallocate paths that the raw path
// is null if not assigned otherwise free it.
// Return ptr to current position or offset from buffer start
int parse_path(uint8_t* buffer, spath_t* path_ptr)
{
  int offset = 0;

  path_ptr->len = buffer[offset++];
  // Allocate the buffer space
  int path_length = path_ptr->len * LINE_LEN;
  path_ptr->raw_path = malloc(path_length);
  // Copy over the path data
  memcpy(path_ptr->raw_path, &buffer[offset], path_length);
  offset += path_length;

  // Copy the border router address
  offset += parse_host_addr(&buffer[offset], &(path_ptr->first_hop));

  return offset;
}

// TODO(jsmith): Always read the full buffer. Will make life easier instead of
// trying to figure out where it stops
int parse_path_record(uint8_t* buffer, spath_record_t* record)
{
  int offset = 0;

  // Parse the path and MTU
  offset += parse_path(buffer, &(record->path));
  // TODO: MTU

}


//     bool add = true;
//     int pathLen = *ptr * 8;
//     if (pathLen + 1 > len)
//         return -1;
//     uint8_t addr_type = *(ptr + 1 + pathLen);
//     int addr_len = get_addr_len(addr_type);
//     // TODO: IPv6 (once sciond supports it)
//     int interfaceOffset = 1 + pathLen + 1 + addr_len + 2 + 2;
//     int interfaceCount = *(ptr + interfaceOffset);
//     if (interfaceOffset + 1 + interfaceCount * IF_TOTAL_LEN > len)
//         return -1;
//     for (size_t j = 0; j < mPaths.size(); j++) {
//         if (mPaths[j] &&
//                 mPaths[j]->isSamePath(ptr + 1, pathLen)) {
//             add = false;
//             break;
//         }
//     }
//     for (size_t j = 0; j < candidates.size(); j++) {
//         if (candidates[j]->usesSameInterfaces(ptr + interfaceOffset + 1, interfaceCount)) {
//             add = false;
//             break;
//         }
//     }
//     if (add) {
//         Path *p = createPath(mDstAddr, ptr, 0);
//         if (mPolicy.validate(p))
//             candidates.push_back(p);
//         else
//             delete p;
//     }
//     return interfaceOffset + 1 + interfaceCount * IF_TOTAL_LEN;


int read_path_response(int sockfd)
{
  uint8_t buffer[DP_HEADER_LEN];
  // Read in the communication header
  int result = recv_all(sockfd, buffer, DP_HEADER_LEN);
  if (result == -1) { return -errno; }

  int packet_len;
  parse_dp_header(buffer, /*addr_len=*/NULL, &packet_len);

}
