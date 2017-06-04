#ifndef _UTILS_H_
#define _UTILS_H_

#define DP_COOKIE_LEN 8
#define DP_HEADER_LEN (DP_COOKIE_LEN + 5)

int validate_cookie(uint8_t *buf);
void parse_dp_header(uint8_t *buf, uint8_t *addr_len, int *packet_len);
void write_dp_header(uint8_t *buf, HostAddr *host, int packet_len);
int send_dp_header(int sock, HostAddr *host, int packet_len);

int recv_all(int sock, uint8_t *buf, int len);
int send_all(int sock, uint8_t *buf, int len);

const char * addr_to_str(uint8_t *addr, uint8_t type, char *buf);
const char * svc_to_str(uint16_t svc, char *buf);

int family_to_type(int family);
int type_to_family(int type);
uint8_t * get_ss_addr(struct sockaddr_storage *ss);

#endif
