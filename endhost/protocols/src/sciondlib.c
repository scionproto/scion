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


/* Parse network byte-order host address and populate the supplied addr with
 * a copy of the data.
 *
 * On success, returns the number of bytes used for the host address. If the
 * remaining input in the buffer, as indicated by data_len, is less than the
 * needed data, zero is returned.
 */
int parse_host_addr(uint8_t* buffer, int data_len, HostAddr* host_addr)
{
  // Fail if we cannot read the address type
  if (data_len == 0) { return 0; }

  // Read the address type and determine if there is enough data
  int offset = 0;
  const uint8_t addr_type = buffer[offset++];  // FIXME(jsmith): Valid type?
  const int addr_len = get_addr_len(addr_type);
  const int port_len = 2;  // Bytes for port number
  if (data_len - offset < port_len + addr_len) { return 0; }

  // Set the address type
  host_addr->addr_type = addr_type;

  // Copy the address data
  memcpy(host_addr->addr, &buffer[offset], addr_len);
  offset += addr_len;

  // Copy the 2-byte port and change its edianness
  host_addr->port = (buffer[offset] << 8) | buffer[offset+1];
  offset += 2;

  return offset;
}


// TODO(jsmith): Is all allocated memory freed in case of failure?
// TODO(jsmith): Function to appropriately free the paths
// TODO(jsmith): Assume that the fucntion to deallocate paths that the raw path
// is null if not assigned otherwise free it.
// Return ptr to current position or offset from buffer start
int parse_path(uint8_t* buffer, int data_len, spath_t* path_ptr)
{
  // Fail if we cannot read the path length
  if (data_len == 0) { return 0; }

  // Check for sufficient path data
  int offset = 0;
  const int path_byte_len = buffer[offset++] * LINE_LEN;
  if (path_byte_len > data_len - offset) { return 0; }

  // First attempt to parse border router address.
  // Avoid dynamic memory usage on failure.
  int n_host_bytes = parse_host_addr(&buffer[offset + path_byte_len],
                                     (data_len - (offset + path_byte_len)),
                                     &(path_ptr->first_hop));
  if (n_host_bytes == 0) { return 0; }

  // Now allocate the buffer space and set the path length
  path_ptr->len = path_byte_len / LINE_LEN;
  path_ptr->raw_path = malloc(path_byte_len);
  // Copy over the path data
  memcpy(path_ptr->raw_path, &buffer[offset], path_byte_len);
  offset += path_byte_len + n_host_bytes;

  return offset;
}

/* De-initializes the specified path, freeing any internally allocated memory.
 * The memory pointed to by the record itself is not freed however.
 */
void destroy_spath(spath_t* path)
{
  free(path->raw_path);
}

int parse_interface(uint8_t* buffer, sinterface_t* interface)
{
  int offset = 0;
  // Read in the 4 byte isd_as address and change to host byte ordering
  memcpy(&interface->isd_as, &buffer[offset], sizeof(interface->isd_as));
  interface->isd_as = ntohl(interface->isd_as);
  offset += sizeof(interface->isd_as);

  // Read the 2-byte link identifier
  interface->link = (buffer[offset] << 8) | buffer[offset+1];
  offset += 2;

  return offset;
}

int parse_interfaces(uint8_t* buffer, int data_len,
                     sinterface_t** interface_array, uint8_t* interface_count)
{
  // Fail if we cannot read the path length
  if (data_len == 0) { return 0; }

  // Check for sufficient path data
  int offset = 0;
  const int interface_length = 6;
  const int interface_byte_len = buffer[offset++] * interface_length;
  if (interface_byte_len > data_len - offset) { return 0; }

  // Parse the interfaces
  *interface_count = buffer[offset-1];
  sinterface_t* interface_ptr =
    malloc(sizeof(sinterface_t) * (*interface_count));

  int i = 0;
  for (i = 0; i < *interface_count; ++i) {
    offset += parse_interface(&buffer[offset], &interface_ptr[i]);
  }

  *interface_array = interface_ptr;
  return offset;
}

// TODO(jsmith): destroy the path on failure
int parse_path_record(uint8_t* buffer, int data_len, spath_record_t* record)
{
  int offset = 0;

  // Parse the path
  int bytes_used = parse_path(&buffer[offset], data_len, &(record->path));
  if (bytes_used == 0) { return 0; }
  offset += bytes_used;

  // Parse the MTU
  if ((data_len - offset) < 2) {
    destroy_spath(&record->path);
    return 0;
  }
  record->mtu = (buffer[offset] << 8) | buffer[offset+1];
  offset += 2;

  // Parse the path's interfaces
  bytes_used = parse_interfaces(&buffer[offset], (data_len - offset),
                                &record->interfaces,
                                &record->interface_count);
  if (bytes_used == 0) {
    destroy_spath(&record->path);
    return 0;
  }

  return offset + bytes_used;
}
