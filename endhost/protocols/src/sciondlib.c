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


int has_same_interfaces(const spath_record_t* record_a,
                        const spath_record_t* record_b)
{
  // Compare the size of the interface list
  if (record_a->interface_count != record_b->interface_count) {
    return 0;
  }
  // Compare the ISD-AS and LINK of each interface used
  int i = 0;
  for (i = 0; i < record_a->interface_count; ++i) {
    if (record_a->interfaces[i].isd_as != record_b->interfaces[i].isd_as ||
        record_a->interfaces[i].link != record_b->interfaces[i].link) {
      return 0;
    }
  }
  return 1;
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


// The host address occupies [ addr_type (1B) | addr (?B) | port (2B) ]
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


// Parses a path of the form
// [ # byte-octets (1B) | path data (?B) | host_addr (?B) ]
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


// Parse an interface with the form [ ISD-AS (4B) | link (2B) ]
// Returns number of bytes parsed and assumes that the data in the buffer is
// sufficient.
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

// Parse interface lists with the form [ # interfaces (1B) | if0 | if1 | ... ]
// Return 0 on failure or the number of bytes used in the parsing.
int parse_interfaces(uint8_t* buffer, int data_len,
                     sinterface_t** interface_array, uint8_t* interface_count)
{
  // Fail if we cannot read the path length
  if (data_len == 0) { return 0; }

  // Check for sufficient path data
  int offset = 0;
  const int interface_byte_len = buffer[offset++] * INTERFACE_LEN;
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


// Parse the path record of the form [ Path | MTU (2B) | Interfaces ]
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


// Free the raw path data and clear the pointer
void destroy_spath(spath_t* path)
{
  free(path->raw_path);
  path->raw_path = NULL;
}


void destroy_spath_record(spath_record_t* record)
{
  // Destroy the path
  destroy_spath(&record->path);
  // Free the interfaces reset the count
  free(record->interfaces);
  record->interfaces = NULL;
  record->interface_count = 0;
}
