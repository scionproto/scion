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
#include <arpa/inet.h>

#include "gtest/gtest.h"

#include "scion.h"
#include "sciondlib.h"

namespace {

// TODO(jsmith): Test memory cleanup & deallocation

/* It should properly parse a simple path daemon record.
 */
TEST(ScionDaemonTest, ParsesRecord)
{
  uint8_t buffer[] = {
    0x01, 'P', 'A', 'T', 'H', 'I', 'N', 'F', 'O',  // Single line of path data
    0x01, 'A','D','D','R', 0xA0, 0x0F,             // Border router on port 0xA00F
    0x05, 0xDC,  // MTU of 1500 bytes
    0x02,        // Two links
    /*ISD-AS*/0x01, 0x00, 0x01, 0x00, /*link*/0x00, 0x64,  // Link 100
    /*ISD-AS*/0x02, 0x00, 0x02, 0x00, /*link*/0x00, 0xC8,  // Link 200
  };

  spath_record_t record;
  int result = parse_path_record(buffer, sizeof(buffer), &record);

  // MTU and # of interfaces should be equal to the expected amounts
  ASSERT_EQ(result, sizeof(buffer));
  EXPECT_EQ(record.mtu, 0x05DC);
  ASSERT_EQ(record.interface_count, 0x02);
  // Check the ISD-AS address and link for the first interface
  EXPECT_EQ(record.interfaces[0].link, 0x64);
  EXPECT_EQ(record.interfaces[0].isd_as, 0x01000100);
  // Check the ISD-AS address and link for the second interface
  EXPECT_EQ(record.interfaces[1].link, 0xC8);
  EXPECT_EQ(record.interfaces[1].isd_as, 0x02000200);
}


/* It should construct a spath_t from the provided binary data.
 */
TEST(ScionDaemonTest, ParsesPath)
{
  uint8_t buffer[] = {
    0x01, 'P', 'A', 'T', 'H', 'I', 'N', 'F', 'O',  // Single line of path data
    0x01, 'A','D','D','R', 0xA0, 0x0F,             // Border router on port 0xA00F
  };

  spath_t path;
  int result = parse_path(buffer, sizeof(buffer), &path);

  ASSERT_EQ(result, sizeof(buffer));
  ASSERT_EQ(path.len, 0x01);
  ASSERT_EQ(path.first_hop.addr_type, 0x01);
  ASSERT_EQ(path.first_hop.port, 0xA00F);
}



}  // namespace
