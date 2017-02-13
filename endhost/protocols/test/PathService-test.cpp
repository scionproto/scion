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
#include <array>
#include <cstdint>
#include <memory>
#include <set>
#include <string>
#include <vector>
#include <algorithm>

#include "gtest/gtest.h"

#include "MockUnixSocket.h"
#include "PathService.h"

extern "C" {
#include "utils.h"
}


using namespace ::testing;

using Buffer = std::vector<uint8_t>;


Buffer& add_path_info(int num_lines, uint8_t tag, Buffer& buffer)
{
  // Ensure the number of path lines can be cast to uint8_t
  assert(num_lines <= 255 && num_lines >= 0);
  // Add the number of path
  buffer.push_back(static_cast<uint8_t>(num_lines));
  for (int i = 0; i < num_lines; ++i) {
    std::array<uint8_t, 8> line = {
      { 'L', 'I', 'N', 'E', '_', '#', static_cast<uint8_t>(i), tag }
    };
    buffer.insert(buffer.end(), line.begin(), line.end());
  }
  return buffer;
}

Buffer& add_interfaces(int num_interfaces, uint8_t isd_tag, uint8_t as_tag,
                       Buffer& buffer)
{
  assert(num_interfaces <= 255 && num_interfaces >= 0);
  // Add the number of path
  buffer.push_back(static_cast<uint8_t>(num_interfaces));
  for (int i = 0; i < num_interfaces; ++i) {
    std::array<uint8_t, 6> interface = {
      { static_cast<uint8_t>(isd_tag), '_', '_', static_cast<uint8_t>(as_tag + i),
        0x00, 0x01  // Link 1
      }
    };
    buffer.insert(buffer.end(), interface.begin(), interface.end());
  }
  return buffer;
}

// Add the address and MTU
Buffer& add_addr_mtu(Buffer& buffer)
{
  std::array<uint8_t, 9> address { { 0x01, 'A', 'D', 'D', 'R', 0xA0, 0x0F, 0x05,
    0xDC } };
  buffer.insert(buffer.end(), address.begin(), address.end());
  return buffer;
}


class PathServiceTest: public Test {
protected:
  void SetUp() override
  {
    // Add three "distinct" paths
    Buffer buffer;
    add_path_info(/*num_lines=*/1, /*tag=*/'A', buffer);
    add_addr_mtu(buffer);
    add_interfaces(/*num_interfaces=*/2, /*isd_tag=*/'A', /*as_tag=*/10, buffer);
    m_daemon_records.push_back(std::move(buffer));

    add_path_info(/*num_lines=*/2, /*tag=*/'B', buffer);
    add_addr_mtu(buffer);
    add_interfaces(/*num_interfaces=*/3, /*isd_tag=*/'A', /*as_tag=*/10, buffer);
    m_daemon_records.push_back(std::move(buffer));

    add_path_info(/*num_lines=*/3, /*tag=*/'C', buffer);
    add_addr_mtu(buffer);
    add_interfaces(/*num_interfaces=*/3, /*isd_tag=*/'A', /*as_tag=*/10, buffer);
    m_daemon_records.push_back(std::move(buffer));

    // This record uses the same interfaces, but different
    add_path_info(/*num_lines=*/3, /*tag=*/'A', buffer);
    add_addr_mtu(buffer);
    add_interfaces(/*num_interfaces=*/2, /*isd_tag=*/'A', /*as_tag=*/10, buffer);
    m_daemon_records.push_back(std::move(buffer));

    // Add three "distinct" paths
    // std::string records[4] {
    //   // One line path info, router on port 0xA00F at IPv4 ADDR, MTU 1500
    //   "\x01""PATHINFO" "\x01""ADDR""\xA0\x0F" "\x05\xDC"
    //   // Links (0x01000100, 100) and (0x02000200, 200)
    //   "\x02" "\x01\x00\x01\x00""\x00\x64" "\x02\x00\x02\x00""\x00\xC8",

    //   // Two lines path info, router on port 0xA00F at IPv4 ADDR, MTU 1500
    //   "\x02""PTHLINE1""PTHLINE2" "\x01""ADDR""\xA0\x0F" "\x05\xDC"
    //   // Links (0x01000100, 100), (0x02000200, 200) and (0x03000300, 300)
    //   "\x03" "\x01\x00\x01\x00""\x00\x64" "\x02\x00\x02\x00""\x00\xC8"
    //          "\x03\x00\x03\x00""\x01\x2C",

    //   // Three lines path info, router on port 0xA00F at IPv4 ADDR, MTU 1500
    //   "\x03""PTHLINE1""PTHLINE2""PTHLINE3" "\x01""ADDR""\xA0\x0F" "\x05\xDC"
    //   // Links (0x01000100, 150), (0x02000200, 200) and (0x03000300, 300)
    //   "\x03" "\x01\x00\x01\x00""\x00\x96" "\x02\x00\x02\x00""\x00\xC8"
    //          "\x03\x00\x03\x00""\x01\x2C",

    //   // Three lines path info, router on port 0xA00F at IPv4 ADDR, MTU 1500
    //   "\x03""LINEPTH1""LINEPTH2""LINEPTH3" "\x01""ADDR""\xA0\x0F" "\x05\xDC"
    //   // Links (0x01000100, 150), (0x02000200, 200) and (0x03000300, 300)
    //   "\x03" "\x01\x00\x01\x00""\x00\x96" "\x02\x00\x02\x00""\x00\xC8"
    //          "\x03\x00\x03\x00""\x01\x2C"
    // };

    // for (const auto& record : records) {
    //   m_daemon_records.push_back(
    //     std::vector<uint8_t>{record.begin(), record.end()}
    //   );
    // }
  }

  // Creates a dp_header in buffer for the first num_records records.
  void expect_response(MockUnixSocket &mock_sock, std::vector<uint8_t> &buffer,
                       int num_records)
  {
    assert(num_records <= m_daemon_records.size());
    int data_size = 0;
    for (int i = 0; i < num_records; ++i) {
      data_size += m_daemon_records[i].size();
    }
    buffer.resize(DP_HEADER_LEN);
    // Write the dispatcher header
    ::write_dp_header(buffer.data(), nullptr, data_size);
    // Write the records
    auto iter = buffer.begin() + DP_HEADER_LEN;
    for (int i = 0; i < num_records; ++i) {
      buffer.insert(iter, m_daemon_records[i].begin(),
                    m_daemon_records[i].end());
      iter = buffer.end();
    }

    auto header_endpoint = buffer.begin() + DP_HEADER_LEN;
    // Set up the expectation for the header and the
    EXPECT_CALL(mock_sock, recv_all(NotNull(), _))
      .WillOnce(DoAll(SetArrayArgument<0>(buffer.begin(), header_endpoint),
                      Return(DP_HEADER_LEN)))
      .WillOnce(DoAll(SetArrayArgument<0>(header_endpoint, buffer.end()),
                      Return(buffer.size() - DP_HEADER_LEN)));

  }

  std::vector<std::vector<uint8_t>> m_daemon_records;
};


TEST_F(PathServiceTest, Foo)
{
  uint32_t isd_as = 99;
  int num_records = 2;
  std::set<int> new_keys;

  // Construct a PathService
  PathService<MockUnixSocket> service{isd_as};

  // Set the expectation for the response
  std::vector<uint8_t> response;
  expect_response(service.m_daemon_sock, response, num_records);

  int result = service.refresh_paths(new_keys);
  ASSERT_EQ(result, 0) << "Should not raise an error.";
  ASSERT_EQ(new_keys.size(), num_records);
}
