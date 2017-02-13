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
#include <cstring>

#include "gtest/gtest.h"

#include "MockUnixSocket.h"
#include "PathService.h"

extern "C" {
#include "utils.h"
}


using namespace ::testing;

using Buffer = std::vector<uint8_t>;

static const Buffer k_address_mtu {
  { 0x01, 'A', 'D', 'D', 'R', 0xA0, 0x0F, 0x05, 0xDC }
};

template <uint8_t A, uint8_t B>
void add_record(const std::array<uint8_t, A*LINE_LEN> &path_lines,
                const std::array<sinterface_t, B> &interfaces,
                std::vector<Buffer> &out)
{
  Buffer bytes;
  // Add the number of path lines and the associated lines
  bytes.push_back(A);
  bytes.insert(bytes.end(), path_lines.begin(), path_lines.end());
  // Add the address
  bytes.insert(bytes.end(), k_address_mtu.begin(), k_address_mtu.end());
  // Add the number of interfaces and the interfaces
  bytes.push_back(B);
  for (const auto& interface : interfaces) {
    uint8_t temp[INTERFACE_LEN];
    uint32_t net_isd_as = htonl(interface.isd_as);
    uint16_t net_link = htons(interface.link);
    std::memcpy(temp, &net_isd_as, sizeof(net_isd_as));
    std::memcpy(&temp[sizeof(interface.isd_as)], &net_link, sizeof(net_link));
    bytes.insert(bytes.end(), temp, &temp[INTERFACE_LEN]);
  }
  // Add it to the out vector
  out.push_back(std::move(bytes));
}


class PathServiceTest: public Test {
protected:
  void SetUp() override
  {
    // Add three "distinct" paths
    add_record<1, 2>({'L', 'I', 'N', 'E', '_', '#', '1', 'A'},
                     {sinterface_t{10, 1}, sinterface_t{11, 2}},
                     m_daemon_records);
    add_record<2, 3>({'L', 'I', 'N', 'E', '_', '#', '1', 'B',
                      'L', 'I', 'N', 'E', '_', '#', '2', 'B'},
                     {sinterface_t{10, 1}, sinterface_t{11, 2},
                      sinterface_t{12, 3}},
                     m_daemon_records);
    add_record<3, 3>({'L', 'I', 'N', 'E', '_', '#', '1', 'C',
                      'L', 'I', 'N', 'E', '_', '#', '2', 'C',
                      'L', 'I', 'N', 'E', '_', '#', '3', 'C'},
                     {sinterface_t{10, 1}, sinterface_t{11, 4},
                      sinterface_t{12, 2}},
                     m_daemon_records);
    // This record uses the same interfaces as the first above, but a different
    // raw path
    add_record<1, 2>({'L', 'I', 'N', 'E', '_', '#', '1', 'D'},
                     {sinterface_t{10, 1}, sinterface_t{11, 2}},
                     m_daemon_records);
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

    // Send will by default always be successful
    ON_CALL(mock_sock, send_all(NotNull(), _))
      .WillByDefault(ReturnArg<1>());

    // Set up the expectation for the header and the
    EXPECT_CALL(mock_sock, recv_all(NotNull(), _))
      .WillOnce(DoAll(SetArrayArgument<0>(buffer.begin(), header_endpoint),
                      Return(DP_HEADER_LEN)))
      .WillOnce(DoAll(SetArrayArgument<0>(header_endpoint, buffer.end()),
                      Return(buffer.size() - DP_HEADER_LEN)));
  }

  std::vector<std::vector<uint8_t>> m_daemon_records;
};


// It should query and store new records.
// - Pre-existing record IDs should not be returned
TEST_F(PathServiceTest, GetsNewRecords)
{
  uint32_t isd_as = 99;

  // Construct a PathService
  PathService<MockUnixSocket> service{isd_as};
  MockUnixSocket &mock_sock = service.m_daemon_sock;

  // It should populate 2 new records
  int num_records = 2;
  std::set<int> new_keys;
  std::vector<uint8_t> response;
  // Set the expectation for the response
  expect_response(mock_sock, response, num_records);

  int result = service.refresh_paths(new_keys);
  ASSERT_EQ(result, 0) << "Should not fail.";
  ASSERT_EQ(new_keys.size(), num_records);
  ASSERT_TRUE(Mock::VerifyAndClearExpectations(&mock_sock));

  // It should add 1 new record
  num_records = 3;
  new_keys.clear();
  response.clear();
  expect_response(mock_sock, response, num_records);

  result = service.refresh_paths(new_keys);
  ASSERT_EQ(result, 0) << "Should not fail.";
  ASSERT_EQ(new_keys.size(), 1);  // Only the 3rd record was unique
  ASSERT_EQ(service.m_records.size(), num_records);
  ASSERT_TRUE(Mock::VerifyAndClearExpectations(&mock_sock));

  // It should add 0 new records as the fourth is identical to the 3rd with
  // respect to interfaces
  num_records = 4;
  new_keys.clear();
  response.clear();
  expect_response(mock_sock, response, num_records);

  result = service.refresh_paths(new_keys);
  ASSERT_EQ(result, 0) << "Should not fail.";
  ASSERT_EQ(new_keys.size(), 0);  // None of the interface lists are unique
  ASSERT_EQ(service.m_records.size(), num_records - 1);  // Ignore duplciate
  ASSERT_TRUE(Mock::VerifyAndClearExpectations(&mock_sock));
}
