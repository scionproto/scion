#ifndef _UTILS_H_
#define _UTILS_H_

#define DP_COOKIE_LEN 8
#define DP_HEADER_LEN (DP_COOKIE_LEN + 5)

int validate_cookie(uint8_t *buf);
void parse_dp_header(uint8_t *buf, int *addr_len, int *packet_len);
void write_dp_header(uint8_t *buf, HostAddr *host, int packet_len);
int send_dp_header(int sock, HostAddr *host, int packet_len);

int recv_all(int sock, uint8_t *buf, int len);
int send_all(int sock, uint8_t *buf, int len);

#endif
