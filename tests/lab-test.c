#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "harness/unity.h"
#include "../src/lab.h"

void setUp(void) {}

void tearDown(void) {}

/* ---------------------------------------------------------------------------
 * Helpers
 * ------------------------------------------------------------------------ */

static cidr_t block(const char *text) {
  cidr_t b = {0, 0};
  TEST_ASSERT_TRUE_MESSAGE(cidr_parse(text, &b), text);
  return b;
}

static uint32_t ip(const char *text) {
  uint32_t a = 0;
  TEST_ASSERT_TRUE_MESSAGE(ip_parse(text, &a), text);
  return a;
}

static route_t route(const char *line) {
  route_t r;
  memset(&r, 0, sizeof r);
  TEST_ASSERT_TRUE_MESSAGE(route_parse(line, &r), line);
  return r;
}

/** Write text to a temporary file and rewind it, ready for table_load(). */
static FILE *file_with(const char *text) {
  FILE *f = tmpfile();
  TEST_ASSERT_NOT_NULL(f);
  fputs(text, f);
  rewind(f);
  return f;
}

#define ASSERT_IP(expected, actual)                                            \
  do {                                                                         \
    char buf_[IP_STR_LEN];                                                     \
    ip_format((actual), buf_);                                                 \
    TEST_ASSERT_EQUAL_STRING((expected), buf_);                                \
  } while (0)

#define ASSERT_CIDR(expected, actual)                                          \
  do {                                                                         \
    char buf_[CIDR_STR_LEN];                                                   \
    cidr_format((actual), buf_);                                               \
    TEST_ASSERT_EQUAL_STRING((expected), buf_);                                \
  } while (0)

/** The table from tables/example.txt, used by several tests. */
static const char *EXAMPLE =
    "# destination      gateway          device\n"
    "default            132.178.227.1    eno1\n"
    "132.178.227.0/25   direct           eno1\n"
    "10.0.0.0/8         10.1.0.1         eth1\n"
    "10.1.0.0/16        direct           eth1\n"
    "10.1.2.0/24        direct           eth2\n"
    "10.1.2.128/25      10.1.2.1         eth2   # a router behind eth2\n"
    "192.168.0.0/16     10.1.0.1         eth1\n";

/* ---------------------------------------------------------------------------
 * Task 1 - ip_parse / ip_format
 * ------------------------------------------------------------------------ */

void test_ip_parse_valid(void) {
  uint32_t a = 0;
  TEST_ASSERT_TRUE(ip_parse("192.168.1.10", &a));
  TEST_ASSERT_EQUAL_HEX32(0xC0A8010A, a);
  TEST_ASSERT_TRUE(ip_parse("0.0.0.0", &a));
  TEST_ASSERT_EQUAL_HEX32(0x00000000, a);
  TEST_ASSERT_TRUE(ip_parse("255.255.255.255", &a));
  TEST_ASSERT_EQUAL_HEX32(0xFFFFFFFF, a);
  TEST_ASSERT_TRUE(ip_parse("132.178.227.11", &a));
  TEST_ASSERT_EQUAL_HEX32(0x84B2E30B, a);
  TEST_ASSERT_TRUE(ip_parse("1.2.3.4", &a));
  TEST_ASSERT_EQUAL_HEX32(0x01020304, a);
  TEST_ASSERT_TRUE(ip_parse("10.0.0.100", &a));
  TEST_ASSERT_EQUAL_HEX32(0x0A000064, a);
}

void test_ip_parse_rejects_wrong_number_of_octets(void) {
  uint32_t a = 0xDEADBEEF;
  TEST_ASSERT_FALSE(ip_parse("1.2.3", &a));
  TEST_ASSERT_FALSE(ip_parse("1.2.3.4.5", &a));
  TEST_ASSERT_FALSE(ip_parse("1", &a));
  TEST_ASSERT_FALSE(ip_parse("", &a));
  TEST_ASSERT_EQUAL_HEX32(0xDEADBEEF, a); // untouched on failure
}

void test_ip_parse_rejects_bad_separators(void) {
  uint32_t a = 0xDEADBEEF;
  TEST_ASSERT_FALSE(ip_parse("1..2.3", &a));
  TEST_ASSERT_FALSE(ip_parse(".1.2.3.4", &a));
  TEST_ASSERT_FALSE(ip_parse("1.2.3.4.", &a));
  TEST_ASSERT_FALSE(ip_parse("1.2.3.", &a));
  TEST_ASSERT_FALSE(ip_parse("1,2,3,4", &a));
  TEST_ASSERT_FALSE(ip_parse("1.2.3 4", &a));
  TEST_ASSERT_EQUAL_HEX32(0xDEADBEEF, a);
}

void test_ip_parse_rejects_out_of_range_octets(void) {
  uint32_t a = 0xDEADBEEF;
  TEST_ASSERT_FALSE(ip_parse("256.1.1.1", &a));
  TEST_ASSERT_FALSE(ip_parse("1.256.1.1", &a));
  TEST_ASSERT_FALSE(ip_parse("1.1.256.1", &a));
  TEST_ASSERT_FALSE(ip_parse("1.1.1.256", &a));
  TEST_ASSERT_FALSE(ip_parse("1.1.1.1000", &a));
  TEST_ASSERT_FALSE(ip_parse("99999999999999999999.1.1.1", &a));
  TEST_ASSERT_EQUAL_HEX32(0xDEADBEEF, a);
}

void test_ip_parse_rejects_leading_zeros(void) {
  uint32_t a = 0xDEADBEEF;
  TEST_ASSERT_FALSE(ip_parse("010.0.0.1", &a));
  TEST_ASSERT_FALSE(ip_parse("1.02.3.4", &a));
  TEST_ASSERT_FALSE(ip_parse("1.2.3.00", &a));
  TEST_ASSERT_FALSE(ip_parse("00.0.0.0", &a));
  TEST_ASSERT_EQUAL_HEX32(0xDEADBEEF, a);
}

void test_ip_parse_rejects_junk(void) {
  uint32_t a = 0xDEADBEEF;
  TEST_ASSERT_FALSE(ip_parse("1.2.3.4x", &a));
  TEST_ASSERT_FALSE(ip_parse(" 1.2.3.4", &a));
  TEST_ASSERT_FALSE(ip_parse("1.2.3.4 ", &a));
  TEST_ASSERT_FALSE(ip_parse("1.2.3.4\n", &a));
  TEST_ASSERT_FALSE(ip_parse("+1.2.3.4", &a));
  TEST_ASSERT_FALSE(ip_parse("-1.2.3.4", &a));
  TEST_ASSERT_FALSE(ip_parse("1.2.3.4/24", &a));
  TEST_ASSERT_FALSE(ip_parse("a.b.c.d", &a));
  TEST_ASSERT_FALSE(ip_parse("0x1.2.3.4", &a));
  TEST_ASSERT_EQUAL_HEX32(0xDEADBEEF, a);
}

void test_ip_parse_null(void) {
  uint32_t a = 0xDEADBEEF;
  TEST_ASSERT_FALSE(ip_parse(NULL, &a));
  TEST_ASSERT_FALSE(ip_parse("1.2.3.4", NULL));
  TEST_ASSERT_EQUAL_HEX32(0xDEADBEEF, a);
}

void test_ip_format(void) {
  char out[IP_STR_LEN];
  ip_format(0xC0A8010A, out);
  TEST_ASSERT_EQUAL_STRING("192.168.1.10", out);
  ip_format(0, out);
  TEST_ASSERT_EQUAL_STRING("0.0.0.0", out);
  ip_format(0xFFFFFFFF, out);
  TEST_ASSERT_EQUAL_STRING("255.255.255.255", out);
  ip_format(0x0A000064, out);
  TEST_ASSERT_EQUAL_STRING("10.0.0.100", out);
}

void test_ip_round_trip(void) {
  const char *samples[] = {"0.0.0.0", "1.2.3.4", "8.8.8.8", "100.64.0.1",
                           "132.178.227.11", "255.255.255.255"};
  for (size_t i = 0; i < sizeof samples / sizeof samples[0]; i++) {
    char out[IP_STR_LEN];
    ip_format(ip(samples[i]), out);
    TEST_ASSERT_EQUAL_STRING(samples[i], out);
  }
}

/* ---------------------------------------------------------------------------
 * Task 1 - cidr_parse / cidr_format
 * ------------------------------------------------------------------------ */

void test_cidr_parse_valid(void) {
  cidr_t b = {0, 0};
  TEST_ASSERT_TRUE(cidr_parse("192.168.1.0/24", &b));
  TEST_ASSERT_EQUAL_HEX32(0xC0A80100, b.addr);
  TEST_ASSERT_EQUAL_UINT8(24, b.prefix);

  // Host bits may be set; this is an interface address
  TEST_ASSERT_TRUE(cidr_parse("132.178.227.11/25", &b));
  TEST_ASSERT_EQUAL_HEX32(0x84B2E30B, b.addr);
  TEST_ASSERT_EQUAL_UINT8(25, b.prefix);

  TEST_ASSERT_TRUE(cidr_parse("0.0.0.0/0", &b));
  TEST_ASSERT_EQUAL_HEX32(0, b.addr);
  TEST_ASSERT_EQUAL_UINT8(0, b.prefix);

  TEST_ASSERT_TRUE(cidr_parse("255.255.255.255/32", &b));
  TEST_ASSERT_EQUAL_HEX32(0xFFFFFFFF, b.addr);
  TEST_ASSERT_EQUAL_UINT8(32, b.prefix);

  TEST_ASSERT_TRUE(cidr_parse("10.0.0.0/8", &b));
  TEST_ASSERT_EQUAL_UINT8(8, b.prefix);
  TEST_ASSERT_TRUE(cidr_parse("10.0.0.0/31", &b));
  TEST_ASSERT_EQUAL_UINT8(31, b.prefix);
}

void test_cidr_parse_rejects_malformed(void) {
  cidr_t b = {0xDEADBEEF, 7};
  TEST_ASSERT_FALSE(cidr_parse("1.2.3.4/33", &b));
  TEST_ASSERT_FALSE(cidr_parse("1.2.3.4/024", &b));
  TEST_ASSERT_FALSE(cidr_parse("1.2.3.4/00", &b));
  TEST_ASSERT_FALSE(cidr_parse("1.2.3.4/", &b));
  TEST_ASSERT_FALSE(cidr_parse("1.2.3/24", &b));
  TEST_ASSERT_FALSE(cidr_parse("1.2.3.4", &b));    // the slash is required
  TEST_ASSERT_FALSE(cidr_parse("1.2.3.4x", &b));
  TEST_ASSERT_FALSE(cidr_parse("1.2.3.4/24x", &b));
  TEST_ASSERT_FALSE(cidr_parse("1.2.3.4/24/", &b));
  TEST_ASSERT_FALSE(cidr_parse("1.2.3.4/-1", &b));
  TEST_ASSERT_FALSE(cidr_parse("1.2.3.4/+8", &b));
  TEST_ASSERT_FALSE(cidr_parse("1.2.3.4/ 8", &b));
  TEST_ASSERT_FALSE(cidr_parse("1.2.3.4 /8", &b));
  TEST_ASSERT_FALSE(cidr_parse("1.2.3.4/100", &b));
  TEST_ASSERT_FALSE(cidr_parse("1.2.3.4/4294967296", &b));
  TEST_ASSERT_FALSE(cidr_parse("010.0.0.1/8", &b));
  TEST_ASSERT_FALSE(cidr_parse("256.1.1.1/8", &b));
  TEST_ASSERT_FALSE(cidr_parse("/24", &b));
  TEST_ASSERT_FALSE(cidr_parse("", &b));
  TEST_ASSERT_EQUAL_HEX32(0xDEADBEEF, b.addr); // untouched on failure
  TEST_ASSERT_EQUAL_UINT8(7, b.prefix);
}

void test_cidr_parse_null(void) {
  cidr_t b = {0xDEADBEEF, 7};
  TEST_ASSERT_FALSE(cidr_parse(NULL, &b));
  TEST_ASSERT_FALSE(cidr_parse("1.2.3.0/24", NULL));
  TEST_ASSERT_EQUAL_HEX32(0xDEADBEEF, b.addr);
}

void test_cidr_format(void) {
  char out[CIDR_STR_LEN];
  cidr_format((cidr_t){0xC0A80100, 24}, out);
  TEST_ASSERT_EQUAL_STRING("192.168.1.0/24", out);
  cidr_format((cidr_t){0, 0}, out);
  TEST_ASSERT_EQUAL_STRING("0.0.0.0/0", out);
  cidr_format((cidr_t){0xFFFFFFFF, 32}, out);
  TEST_ASSERT_EQUAL_STRING("255.255.255.255/32", out);
  // The address is written exactly as stored, host bits and all
  cidr_format((cidr_t){0x84B2E30B, 25}, out);
  TEST_ASSERT_EQUAL_STRING("132.178.227.11/25", out);
  // A prefix over 32 is written as 32
  cidr_format((cidr_t){0x01020304, 33}, out);
  TEST_ASSERT_EQUAL_STRING("1.2.3.4/32", out);
  cidr_format((cidr_t){0xFFFFFFFF, 255}, out);
  TEST_ASSERT_EQUAL_STRING("255.255.255.255/32", out);
}

void test_cidr_round_trip(void) {
  const char *samples[] = {"0.0.0.0/0", "10.0.0.0/8", "132.178.227.11/25",
                           "192.168.1.0/24", "10.0.0.0/31", "255.255.255.255/32"};
  for (size_t i = 0; i < sizeof samples / sizeof samples[0]; i++) {
    ASSERT_CIDR(samples[i], block(samples[i]));
  }
}

/* ---------------------------------------------------------------------------
 * Task 2 - Subnet arithmetic
 * ------------------------------------------------------------------------ */

void test_cidr_mask(void) {
  TEST_ASSERT_EQUAL_HEX32(0x00000000, cidr_mask(0));
  TEST_ASSERT_EQUAL_HEX32(0x80000000, cidr_mask(1));
  TEST_ASSERT_EQUAL_HEX32(0xFF000000, cidr_mask(8));
  TEST_ASSERT_EQUAL_HEX32(0xFFFF0000, cidr_mask(16));
  TEST_ASSERT_EQUAL_HEX32(0xFFFFFF00, cidr_mask(24));
  TEST_ASSERT_EQUAL_HEX32(0xFFFFFF80, cidr_mask(25));
  TEST_ASSERT_EQUAL_HEX32(0xFFFFFFFC, cidr_mask(30));
  TEST_ASSERT_EQUAL_HEX32(0xFFFFFFFE, cidr_mask(31));
  TEST_ASSERT_EQUAL_HEX32(0xFFFFFFFF, cidr_mask(32));
  TEST_ASSERT_EQUAL_HEX32(0xFFFFFFFF, cidr_mask(33));
  TEST_ASSERT_EQUAL_HEX32(0xFFFFFFFF, cidr_mask(255));
}

void test_cidr_mask_every_prefix(void) {
  for (uint8_t p = 0; p <= 32; p++) {
    uint32_t mask = cidr_mask(p);
    // p leading ones followed by zeros
    uint32_t ones = 0;
    for (uint32_t m = mask; m & 0x80000000u; m <<= 1) {
      ones++;
    }
    TEST_ASSERT_EQUAL_UINT32(p, ones);
    TEST_ASSERT_EQUAL_HEX32(0, (uint32_t)((uint64_t)mask << ones)); // and then only zeros
  }
}

void test_onyx_subnet(void) {
  cidr_t onyx = block("132.178.227.11/25");
  ASSERT_IP("132.178.227.0", cidr_network(onyx));
  ASSERT_IP("132.178.227.127", cidr_broadcast(onyx));
  ASSERT_IP("132.178.227.1", cidr_first_host(onyx));
  ASSERT_IP("132.178.227.126", cidr_last_host(onyx));
  TEST_ASSERT_EQUAL_UINT64(126, cidr_host_count(onyx));
  TEST_ASSERT_TRUE(cidr_contains(onyx, ip("132.178.227.50")));
  TEST_ASSERT_FALSE(cidr_contains(onyx, ip("132.178.227.200")));
  TEST_ASSERT_FALSE(cidr_is_network(onyx));
}

void test_cidr_network_and_broadcast(void) {
  cidr_t b = block("192.168.1.77/24");
  ASSERT_IP("192.168.1.0", cidr_network(b));
  ASSERT_IP("192.168.1.255", cidr_broadcast(b));
  b = block("10.20.30.40/8");
  ASSERT_IP("10.0.0.0", cidr_network(b));
  ASSERT_IP("10.255.255.255", cidr_broadcast(b));
  b = block("172.16.5.9/12");
  ASSERT_IP("172.16.0.0", cidr_network(b));
  ASSERT_IP("172.31.255.255", cidr_broadcast(b));
  b = block("10.0.0.5/30");
  ASSERT_IP("10.0.0.4", cidr_network(b));
  ASSERT_IP("10.0.0.7", cidr_broadcast(b));
}

void test_prefix_0(void) {
  cidr_t all = block("0.0.0.0/0");
  ASSERT_IP("0.0.0.0", cidr_network(all));
  ASSERT_IP("255.255.255.255", cidr_broadcast(all));
  ASSERT_IP("0.0.0.1", cidr_first_host(all));
  ASSERT_IP("255.255.255.254", cidr_last_host(all));
  TEST_ASSERT_EQUAL_UINT64(4294967294ULL, cidr_host_count(all));
  TEST_ASSERT_TRUE(cidr_contains(all, 0));
  TEST_ASSERT_TRUE(cidr_contains(all, 0xFFFFFFFF));
  TEST_ASSERT_TRUE(cidr_contains(all, ip("8.8.8.8")));
  TEST_ASSERT_TRUE(cidr_is_network(all));

  // Any address with a /0 is the same block
  cidr_t odd = block("1.2.3.4/0");
  ASSERT_IP("0.0.0.0", cidr_network(odd));
  ASSERT_IP("255.255.255.255", cidr_broadcast(odd));
  TEST_ASSERT_TRUE(cidr_contains(odd, ip("200.1.1.1")));
  TEST_ASSERT_FALSE(cidr_is_network(odd));
}

void test_prefix_1(void) {
  cidr_t low = block("0.0.0.0/1");
  ASSERT_IP("127.255.255.255", cidr_broadcast(low));
  TEST_ASSERT_EQUAL_UINT64(2147483646ULL, cidr_host_count(low));
  TEST_ASSERT_TRUE(cidr_contains(low, ip("127.0.0.1")));
  TEST_ASSERT_FALSE(cidr_contains(low, ip("128.0.0.1")));
}

void test_prefix_30(void) {
  cidr_t b = block("10.0.0.4/30");
  ASSERT_IP("10.0.0.5", cidr_first_host(b));
  ASSERT_IP("10.0.0.6", cidr_last_host(b));
  TEST_ASSERT_EQUAL_UINT64(2, cidr_host_count(b));
}

void test_prefix_31(void) {
  cidr_t link = block("10.0.0.6/31");
  ASSERT_IP("10.0.0.6", cidr_network(link));
  ASSERT_IP("10.0.0.7", cidr_broadcast(link));
  // RFC 3021: both addresses are hosts
  ASSERT_IP("10.0.0.6", cidr_first_host(link));
  ASSERT_IP("10.0.0.7", cidr_last_host(link));
  TEST_ASSERT_EQUAL_UINT64(2, cidr_host_count(link));
  TEST_ASSERT_TRUE(cidr_contains(link, ip("10.0.0.6")));
  TEST_ASSERT_TRUE(cidr_contains(link, ip("10.0.0.7")));
  TEST_ASSERT_FALSE(cidr_contains(link, ip("10.0.0.5")));
  TEST_ASSERT_FALSE(cidr_contains(link, ip("10.0.0.8")));
  TEST_ASSERT_TRUE(cidr_is_network(link));
  TEST_ASSERT_FALSE(cidr_is_network(block("10.0.0.7/31")));

  cidr_t top = block("255.255.255.254/31");
  ASSERT_IP("255.255.255.254", cidr_first_host(top));
  ASSERT_IP("255.255.255.255", cidr_last_host(top));
}

void test_prefix_32(void) {
  cidr_t host = block("192.168.1.10/32");
  ASSERT_IP("192.168.1.10", cidr_network(host));
  ASSERT_IP("192.168.1.10", cidr_broadcast(host));
  ASSERT_IP("192.168.1.10", cidr_first_host(host));
  ASSERT_IP("192.168.1.10", cidr_last_host(host));
  TEST_ASSERT_EQUAL_UINT64(1, cidr_host_count(host));
  TEST_ASSERT_TRUE(cidr_contains(host, ip("192.168.1.10")));
  TEST_ASSERT_FALSE(cidr_contains(host, ip("192.168.1.11")));
  TEST_ASSERT_TRUE(cidr_is_network(host));

  cidr_t zero = block("0.0.0.0/32");
  ASSERT_IP("0.0.0.0", cidr_first_host(zero));
  ASSERT_IP("0.0.0.0", cidr_last_host(zero));
  TEST_ASSERT_FALSE(cidr_contains(zero, 1));

  cidr_t top = block("255.255.255.255/32");
  ASSERT_IP("255.255.255.255", cidr_first_host(top));
  ASSERT_IP("255.255.255.255", cidr_last_host(top));
  TEST_ASSERT_TRUE(cidr_contains(top, 0xFFFFFFFF));
  TEST_ASSERT_FALSE(cidr_contains(top, 0xFFFFFFFE));
}

void test_prefix_over_32_is_32(void) {
  cidr_t b = {0x01020304, 40};
  TEST_ASSERT_EQUAL_HEX32(0x01020304, cidr_network(b));
  TEST_ASSERT_EQUAL_HEX32(0x01020304, cidr_broadcast(b));
  TEST_ASSERT_EQUAL_HEX32(0x01020304, cidr_first_host(b));
  TEST_ASSERT_EQUAL_HEX32(0x01020304, cidr_last_host(b));
  TEST_ASSERT_EQUAL_UINT64(1, cidr_host_count(b));
  TEST_ASSERT_TRUE(cidr_contains(b, 0x01020304));
  TEST_ASSERT_FALSE(cidr_contains(b, 0x01020305));
  TEST_ASSERT_TRUE(cidr_is_network(b));
}

void test_host_count_every_prefix(void) {
  for (uint8_t p = 0; p <= 30; p++) {
    cidr_t b = {0, p};
    TEST_ASSERT_EQUAL_UINT64((1ULL << (32 - p)) - 2, cidr_host_count(b));
    // first..last spans exactly the host count
    TEST_ASSERT_EQUAL_UINT64(cidr_host_count(b),
                             (uint64_t)cidr_last_host(b) - cidr_first_host(b) + 1);
  }
}

void test_cidr_contains(void) {
  cidr_t b = block("10.1.2.0/24");
  TEST_ASSERT_TRUE(cidr_contains(b, ip("10.1.2.0")));
  TEST_ASSERT_TRUE(cidr_contains(b, ip("10.1.2.255")));
  TEST_ASSERT_TRUE(cidr_contains(b, ip("10.1.2.128")));
  TEST_ASSERT_FALSE(cidr_contains(b, ip("10.1.1.255")));
  TEST_ASSERT_FALSE(cidr_contains(b, ip("10.1.3.0")));
  TEST_ASSERT_FALSE(cidr_contains(b, ip("11.1.2.0")));
  // The block's own host bits do not matter
  TEST_ASSERT_TRUE(cidr_contains(block("10.1.2.99/24"), ip("10.1.2.5")));
}

void test_cidr_is_network(void) {
  TEST_ASSERT_TRUE(cidr_is_network(block("192.168.1.0/24")));
  TEST_ASSERT_FALSE(cidr_is_network(block("192.168.1.5/24")));
  TEST_ASSERT_TRUE(cidr_is_network(block("10.0.0.0/8")));
  TEST_ASSERT_FALSE(cidr_is_network(block("10.0.0.1/8")));
  TEST_ASSERT_TRUE(cidr_is_network(block("132.178.227.128/25")));
  TEST_ASSERT_FALSE(cidr_is_network(block("132.178.227.129/25")));
  TEST_ASSERT_TRUE(cidr_is_network(block("255.255.255.255/32")));
}

/* ---------------------------------------------------------------------------
 * Task 2 - cidr_subnet
 * ------------------------------------------------------------------------ */

void test_cidr_subnet_split_24_into_4(void) {
  cidr_t b = block("192.168.1.0/24");
  cidr_t s;
  const char *expect[] = {"192.168.1.0/26", "192.168.1.64/26", "192.168.1.128/26",
                          "192.168.1.192/26"};
  for (uint32_t i = 0; i < 4; i++) {
    TEST_ASSERT_TRUE(cidr_subnet(b, 4, i, &s));
    ASSERT_CIDR(expect[i], s);
    TEST_ASSERT_TRUE(cidr_is_network(s));
  }
}

void test_cidr_subnet_into_1_is_itself(void) {
  cidr_t s;
  TEST_ASSERT_TRUE(cidr_subnet(block("10.0.0.0/8"), 1, 0, &s));
  ASSERT_CIDR("10.0.0.0/8", s);
  TEST_ASSERT_TRUE(cidr_subnet(block("0.0.0.0/0"), 1, 0, &s));
  ASSERT_CIDR("0.0.0.0/0", s);
  TEST_ASSERT_TRUE(cidr_subnet(block("1.2.3.4/32"), 1, 0, &s));
  ASSERT_CIDR("1.2.3.4/32", s);
}

void test_cidr_subnet_from_0(void) {
  cidr_t all = block("0.0.0.0/0");
  cidr_t s;
  TEST_ASSERT_TRUE(cidr_subnet(all, 2, 0, &s));
  ASSERT_CIDR("0.0.0.0/1", s);
  TEST_ASSERT_TRUE(cidr_subnet(all, 2, 1, &s));
  ASSERT_CIDR("128.0.0.0/1", s);
  TEST_ASSERT_TRUE(cidr_subnet(all, 256, 10, &s));
  ASSERT_CIDR("10.0.0.0/8", s);
  // 2^31 pieces is legal: each one is a /31
  TEST_ASSERT_TRUE(cidr_subnet(all, 0x80000000u, 0x7FFFFFFFu, &s));
  ASSERT_CIDR("255.255.255.254/31", s);
  TEST_ASSERT_TRUE(cidr_subnet(all, 0x80000000u, 0, &s));
  ASSERT_CIDR("0.0.0.0/31", s);
}

void test_cidr_subnet_to_31_and_32(void) {
  cidr_t b = block("10.0.0.0/30");
  cidr_t s;
  TEST_ASSERT_TRUE(cidr_subnet(b, 2, 1, &s));
  ASSERT_CIDR("10.0.0.2/31", s);
  TEST_ASSERT_TRUE(cidr_subnet(b, 4, 3, &s));
  ASSERT_CIDR("10.0.0.3/32", s);
  TEST_ASSERT_TRUE(cidr_subnet(block("10.0.0.0/31"), 2, 1, &s));
  ASSERT_CIDR("10.0.0.1/32", s);
  TEST_ASSERT_TRUE(cidr_subnet(block("255.255.255.0/24"), 256, 255, &s));
  ASSERT_CIDR("255.255.255.255/32", s);
}

void test_cidr_subnet_failures(void) {
  cidr_t s = {0xDEADBEEF, 7};
  cidr_t b = block("192.168.1.0/24");
  TEST_ASSERT_FALSE(cidr_subnet(b, 4, 0, NULL));
  TEST_ASSERT_FALSE(cidr_subnet(block("192.168.1.5/24"), 4, 0, &s)); // not a network
  TEST_ASSERT_FALSE(cidr_subnet(b, 0, 0, &s));                       // not a power of two
  TEST_ASSERT_FALSE(cidr_subnet(b, 3, 0, &s));
  TEST_ASSERT_FALSE(cidr_subnet(b, 6, 0, &s));
  TEST_ASSERT_FALSE(cidr_subnet(b, 0xFFFFFFFFu, 0, &s));
  TEST_ASSERT_FALSE(cidr_subnet(b, 512, 0, &s));                      // would pass /32
  TEST_ASSERT_FALSE(cidr_subnet(block("1.2.3.4/32"), 2, 0, &s));
  TEST_ASSERT_FALSE(cidr_subnet(b, 4, 4, &s));                        // i out of range
  TEST_ASSERT_FALSE(cidr_subnet(b, 1, 1, &s));
  TEST_ASSERT_FALSE(cidr_subnet(b, 4, 0xFFFFFFFFu, &s));
  TEST_ASSERT_EQUAL_HEX32(0xDEADBEEF, s.addr); // untouched on failure
  TEST_ASSERT_EQUAL_UINT8(7, s.prefix);
}

void test_cidr_subnet_covers_block(void) {
  // Every piece is adjacent to the next and together they cover the block
  cidr_t b = block("172.16.0.0/12");
  uint32_t expected = cidr_network(b);
  for (uint32_t i = 0; i < 16; i++) {
    cidr_t s;
    TEST_ASSERT_TRUE(cidr_subnet(b, 16, i, &s));
    TEST_ASSERT_EQUAL_UINT8(16, s.prefix);
    TEST_ASSERT_EQUAL_HEX32(expected, cidr_network(s));
    TEST_ASSERT_TRUE(cidr_contains(b, cidr_broadcast(s)));
    expected = cidr_broadcast(s) + 1;
  }
  TEST_ASSERT_EQUAL_HEX32(cidr_broadcast(b) + 1, expected);
}

/* ---------------------------------------------------------------------------
 * Task 3 - route_parse
 * ------------------------------------------------------------------------ */

void test_route_parse_valid(void) {
  route_t r = route("10.1.2.128/25 10.1.2.1 eth2");
  ASSERT_CIDR("10.1.2.128/25", r.dest);
  ASSERT_IP("10.1.2.1", r.gateway);
  TEST_ASSERT_EQUAL_STRING("eth2", r.dev);

  r = route("default 132.178.227.1 eno1");
  ASSERT_CIDR("0.0.0.0/0", r.dest);
  ASSERT_IP("132.178.227.1", r.gateway);
  TEST_ASSERT_EQUAL_STRING("eno1", r.dev);

  r = route("132.178.227.0/25 direct eno1");
  ASSERT_CIDR("132.178.227.0/25", r.dest);
  TEST_ASSERT_EQUAL_HEX32(0, r.gateway);

  r = route("0.0.0.0/0 direct lo");
  ASSERT_CIDR("0.0.0.0/0", r.dest);
  r = route("1.2.3.4/32 direct x");
  ASSERT_CIDR("1.2.3.4/32", r.dest);
  TEST_ASSERT_EQUAL_STRING("x", r.dev);
}

void test_route_parse_whitespace(void) {
  route_t r = route("  \t10.0.0.0/8\t\t10.1.0.1   eth1  \n");
  ASSERT_CIDR("10.0.0.0/8", r.dest);
  ASSERT_IP("10.1.0.1", r.gateway);
  TEST_ASSERT_EQUAL_STRING("eth1", r.dev);
  r = route("10.0.0.0/8 direct eth1\r\n");
  TEST_ASSERT_EQUAL_STRING("eth1", r.dev);
  r = route("\v\f10.0.0.0/8 direct eth1\f\v");
  TEST_ASSERT_EQUAL_STRING("eth1", r.dev);
}

void test_route_parse_device_length(void) {
  route_t r = route("10.0.0.0/8 direct eno12399np0");
  TEST_ASSERT_EQUAL_STRING("eno12399np0", r.dev);
  r = route("10.0.0.0/8 direct 123456789012345"); // DEV_NAME_LEN - 1
  TEST_ASSERT_EQUAL_STRING("123456789012345", r.dev);
  route_t bad;
  TEST_ASSERT_FALSE(route_parse("10.0.0.0/8 direct 1234567890123456", &bad));
}

void test_route_parse_rejects(void) {
  route_t r;
  memset(&r, 0xAB, sizeof r);
  route_t before = r;
  const char *bad[] = {
      "",
      "   \n",
      "10.0.0.0/8",
      "10.0.0.0/8 direct",
      "10.0.0.0/8 direct eth0 extra",
      "10.0.0.1/8 direct eth0",            // host bits set
      "10.0.0.0 direct eth0",              // no prefix
      "10.0.0.0/33 direct eth0",
      "255.255.255.255/32x direct eth0",   // destination field too long
      "10.0.0.0/8 10.0.0 eth0",
      "10.0.0.0/8 010.0.0.1 eth0",
      "10.0.0.0/8 255.255.255.255x eth0",  // gateway field too long
      "10.0.0.0/8 indirect eth0",
      "Default 1.2.3.4 eth0",
      "default/0 1.2.3.4 eth0",
      "10.0.0.0/8 direct et\rh0",          // whitespace inside the device
      "10.0.0.0/8,direct,eth0",
  };
  for (size_t i = 0; i < sizeof bad / sizeof bad[0]; i++) {
    TEST_ASSERT_FALSE_MESSAGE(route_parse(bad[i], &r), bad[i]);
  }
  TEST_ASSERT_EQUAL_MEMORY(&before, &r, sizeof r); // untouched on failure
  TEST_ASSERT_FALSE(route_parse(NULL, &r));
  TEST_ASSERT_FALSE(route_parse("10.0.0.0/8 direct eth0", NULL));
}

/* ---------------------------------------------------------------------------
 * Task 3 - The table
 * ------------------------------------------------------------------------ */

void test_table_create_destroy(void) {
  fwd_table_t *t = table_create();
  TEST_ASSERT_NOT_NULL(t);
  TEST_ASSERT_EQUAL_size_t(0, table_count(t));
  TEST_ASSERT_NULL(table_lookup(t, ip("8.8.8.8")));
  table_destroy(t);
  table_destroy(NULL); // allowed
  TEST_ASSERT_EQUAL_size_t(0, table_count(NULL));
  TEST_ASSERT_NULL(table_lookup(NULL, 0));
}

void test_table_add(void) {
  fwd_table_t *t = table_create();
  route_t r = route("10.0.0.0/8 10.1.0.1 eth1");
  TEST_ASSERT_TRUE(table_add(t, &r));
  TEST_ASSERT_EQUAL_size_t(1, table_count(t));

  // The table holds a copy
  r.gateway = 0;
  strcpy(r.dev, "changed");
  const route_t *got = table_lookup(t, ip("10.9.9.9"));
  TEST_ASSERT_NOT_NULL(got);
  ASSERT_IP("10.1.0.1", got->gateway);
  TEST_ASSERT_EQUAL_STRING("eth1", got->dev);
  TEST_ASSERT_NOT_EQUAL(&r, got);
  table_destroy(t);
}

void test_table_add_rejects(void) {
  fwd_table_t *t = table_create();
  route_t r = route("10.0.0.0/8 10.1.0.1 eth1");
  TEST_ASSERT_FALSE(table_add(NULL, &r));
  TEST_ASSERT_FALSE(table_add(t, NULL));
  TEST_ASSERT_TRUE(table_add(t, &r));

  // A second route to the same block, even with a different next hop
  route_t dup = route("10.0.0.0/8 direct eth9");
  TEST_ASSERT_FALSE(table_add(t, &dup));
  // The same address with a different prefix is a different block
  route_t other = route("10.0.0.0/16 direct eth9");
  TEST_ASSERT_TRUE(table_add(t, &other));
  // The same prefix with a different address is a different block too
  route_t other2 = route("11.0.0.0/8 direct eth9");
  TEST_ASSERT_TRUE(table_add(t, &other2));

  // Host bits set
  route_t host = r;
  host.dest.addr = ip("10.0.0.1");
  TEST_ASSERT_FALSE(table_add(t, &host));

  TEST_ASSERT_EQUAL_size_t(3, table_count(t));
  const route_t *got = table_lookup(t, ip("10.0.0.1"));
  TEST_ASSERT_NOT_NULL(got);
  TEST_ASSERT_EQUAL_STRING("eth9", got->dev); // the /16, unchanged by the failures
  table_destroy(t);
}

void test_table_add_prefix_over_32(void) {
  fwd_table_t *t = table_create();
  route_t r = route("1.2.3.4/32 direct a");
  TEST_ASSERT_TRUE(table_add(t, &r));
  route_t same = r;
  same.dest.prefix = 40; // treated as /32, so the same block
  TEST_ASSERT_FALSE(table_add(t, &same));
  TEST_ASSERT_EQUAL_size_t(1, table_count(t));
  table_destroy(t);
}

void test_table_add_unterminated_device(void) {
  fwd_table_t *t = table_create();
  route_t r = route("10.0.0.0/8 direct eth0");
  memset(r.dev, 'x', sizeof r.dev); // no '\0' anywhere
  TEST_ASSERT_TRUE(table_add(t, &r));
  const route_t *got = table_lookup(t, ip("10.0.0.1"));
  TEST_ASSERT_NOT_NULL(got);
  TEST_ASSERT_EQUAL_size_t(DEV_NAME_LEN - 1, strlen(got->dev));
  table_destroy(t);
}

void test_table_grows(void) {
  fwd_table_t *t = table_create();
  // Enough /24s to force several reallocations
  for (uint32_t i = 0; i < 1000; i++) {
    route_t r;
    memset(&r, 0, sizeof r);
    r.dest.addr = 0x0A000000u | (i << 8);
    r.dest.prefix = 24;
    r.gateway = i + 1;
    snprintf(r.dev, sizeof r.dev, "eth%u", (unsigned)i);
    TEST_ASSERT_TRUE(table_add(t, &r));
  }
  TEST_ASSERT_EQUAL_size_t(1000, table_count(t));
  for (uint32_t i = 0; i < 1000; i += 37) {
    const route_t *got = table_lookup(t, 0x0A000000u | (i << 8) | 42);
    TEST_ASSERT_NOT_NULL(got);
    TEST_ASSERT_EQUAL_UINT32(i + 1, got->gateway);
  }
  TEST_ASSERT_NULL(table_lookup(t, ip("10.255.0.1")));
  table_destroy(t);
}

/* ---------------------------------------------------------------------------
 * Task 3 - Longest prefix match
 * ------------------------------------------------------------------------ */

static void add_all(fwd_table_t *t, const char *lines[], const size_t order[], size_t n) {
  for (size_t i = 0; i < n; i++) {
    route_t r = route(lines[order[i]]);
    TEST_ASSERT_TRUE_MESSAGE(table_add(t, &r), lines[order[i]]);
  }
}

static const char *NESTED[] = {
    "10.0.0.0/8 10.0.0.1 a",
    "10.1.0.0/16 10.1.0.1 b",
    "10.1.2.0/24 direct c",
    "10.1.2.128/25 10.1.2.1 d",
};

static void check_nested(const fwd_table_t *t) {
  // 10.1.2.200 is inside all four; the /25 wins
  const route_t *got = table_lookup(t, ip("10.1.2.200"));
  TEST_ASSERT_NOT_NULL(got);
  TEST_ASSERT_EQUAL_STRING("d", got->dev);
  TEST_ASSERT_EQUAL_UINT8(25, got->dest.prefix);
  TEST_ASSERT_EQUAL_STRING("c", table_lookup(t, ip("10.1.2.5"))->dev);
  TEST_ASSERT_EQUAL_STRING("c", table_lookup(t, ip("10.1.2.127"))->dev);
  TEST_ASSERT_EQUAL_STRING("d", table_lookup(t, ip("10.1.2.128"))->dev);
  TEST_ASSERT_EQUAL_STRING("b", table_lookup(t, ip("10.1.3.1"))->dev);
  TEST_ASSERT_EQUAL_STRING("a", table_lookup(t, ip("10.2.0.1"))->dev);
  // No default route, so anything else is unreachable
  TEST_ASSERT_NULL(table_lookup(t, ip("11.0.0.1")));
  TEST_ASSERT_NULL(table_lookup(t, ip("8.8.8.8")));
  TEST_ASSERT_NULL(table_lookup(t, 0));
  TEST_ASSERT_NULL(table_lookup(t, 0xFFFFFFFF));
}

void test_lookup_longest_prefix_wins(void) {
  const size_t shortest_first[] = {0, 1, 2, 3};
  fwd_table_t *t = table_create();
  add_all(t, NESTED, shortest_first, 4);
  check_nested(t);
  table_destroy(t);
}

void test_lookup_order_does_not_matter(void) {
  const size_t orders[][4] = {
      {3, 2, 1, 0}, {2, 0, 3, 1}, {1, 3, 0, 2}, {0, 3, 1, 2}, {3, 0, 2, 1},
  };
  for (size_t o = 0; o < sizeof orders / sizeof orders[0]; o++) {
    fwd_table_t *t = table_create();
    add_all(t, NESTED, orders[o], 4);
    check_nested(t);
    table_destroy(t);
  }
}

void test_lookup_default_route(void) {
  const char *lines[] = {"default 192.168.0.1 wan", "192.168.0.0/24 direct lan"};
  const size_t default_first[] = {0, 1};
  const size_t default_last[] = {1, 0};
  for (int pass = 0; pass < 2; pass++) {
    fwd_table_t *t = table_create();
    add_all(t, lines, pass == 0 ? default_first : default_last, 2);
    // The default loses to anything more specific...
    TEST_ASSERT_EQUAL_STRING("lan", table_lookup(t, ip("192.168.0.77"))->dev);
    // ...and catches everything else, including both ends of the space
    TEST_ASSERT_EQUAL_STRING("wan", table_lookup(t, ip("8.8.8.8"))->dev);
    TEST_ASSERT_EQUAL_STRING("wan", table_lookup(t, 0)->dev);
    TEST_ASSERT_EQUAL_STRING("wan", table_lookup(t, 0xFFFFFFFF)->dev);
    TEST_ASSERT_EQUAL_UINT8(0, table_lookup(t, 0xFFFFFFFF)->dest.prefix);
    table_destroy(t);
  }
}

void test_lookup_host_and_point_to_point_routes(void) {
  const char *lines[] = {
      "default 1.1.1.1 wan",
      "10.0.0.0/30 direct p2p30",
      "10.0.0.0/31 direct p2p31",
      "10.0.0.1/32 direct host",
      "255.255.255.255/32 direct bcast",
  };
  const size_t order[] = {4, 0, 3, 1, 2};
  fwd_table_t *t = table_create();
  add_all(t, lines, order, 5);
  TEST_ASSERT_EQUAL_STRING("p2p31", table_lookup(t, ip("10.0.0.0"))->dev);
  TEST_ASSERT_EQUAL_STRING("host", table_lookup(t, ip("10.0.0.1"))->dev);
  TEST_ASSERT_EQUAL_STRING("p2p30", table_lookup(t, ip("10.0.0.2"))->dev);
  TEST_ASSERT_EQUAL_STRING("p2p30", table_lookup(t, ip("10.0.0.3"))->dev);
  TEST_ASSERT_EQUAL_STRING("wan", table_lookup(t, ip("10.0.0.4"))->dev);
  TEST_ASSERT_EQUAL_STRING("bcast", table_lookup(t, 0xFFFFFFFF)->dev);
  TEST_ASSERT_EQUAL_STRING("wan", table_lookup(t, 0xFFFFFFFE)->dev);
  table_destroy(t);
}

/* ---------------------------------------------------------------------------
 * Task 3 - table_load
 * ------------------------------------------------------------------------ */

void test_table_load_example(void) {
  fwd_table_t *t = table_create();
  FILE *f = file_with(EXAMPLE);
  size_t bad = 99;
  TEST_ASSERT_TRUE(table_load(t, f, &bad));
  fclose(f);
  TEST_ASSERT_EQUAL_size_t(0, bad);
  TEST_ASSERT_EQUAL_size_t(7, table_count(t));

  // The four lookups from the assignment
  const route_t *r = table_lookup(t, ip("132.178.227.50"));
  TEST_ASSERT_EQUAL_STRING("eno1", r->dev);
  TEST_ASSERT_EQUAL_HEX32(0, r->gateway);
  r = table_lookup(t, ip("8.8.8.8"));
  TEST_ASSERT_EQUAL_STRING("eno1", r->dev);
  ASSERT_IP("132.178.227.1", r->gateway);
  r = table_lookup(t, ip("10.1.2.5"));
  TEST_ASSERT_EQUAL_STRING("eth2", r->dev);
  TEST_ASSERT_EQUAL_HEX32(0, r->gateway);
  r = table_lookup(t, ip("10.1.2.200"));
  TEST_ASSERT_EQUAL_STRING("eth2", r->dev);
  ASSERT_IP("10.1.2.1", r->gateway);

  // And a few more
  r = table_lookup(t, ip("132.178.227.200")); // outside Onyx's /25
  ASSERT_IP("132.178.227.1", r->gateway);
  r = table_lookup(t, ip("192.168.44.1"));
  ASSERT_IP("10.1.0.1", r->gateway);
  TEST_ASSERT_EQUAL_STRING("eth1", r->dev);
  r = table_lookup(t, ip("10.200.0.1"));
  ASSERT_IP("10.1.0.1", r->gateway);
  r = table_lookup(t, ip("10.1.200.1"));
  TEST_ASSERT_EQUAL_HEX32(0, r->gateway);
  TEST_ASSERT_EQUAL_STRING("eth1", r->dev);
  table_destroy(t);
}

void test_table_load_comments_and_blank_lines(void) {
  fwd_table_t *t = table_create();
  FILE *f = file_with("\n"
                      "# only a comment\n"
                      "   # indented comment\n"
                      "\t \n"
                      "10.0.0.0/8 direct eth0#no space before the comment\n"
                      "#10.0.0.0/8 direct eth0\n"
                      "11.0.0.0/8 direct eth1"); // no newline at the end
  size_t bad = 99;
  TEST_ASSERT_TRUE(table_load(t, f, &bad));
  fclose(f);
  TEST_ASSERT_EQUAL_size_t(0, bad);
  TEST_ASSERT_EQUAL_size_t(2, table_count(t));
  TEST_ASSERT_EQUAL_STRING("eth0", table_lookup(t, ip("10.0.0.1"))->dev);
  TEST_ASSERT_EQUAL_STRING("eth1", table_lookup(t, ip("11.0.0.1"))->dev);
  table_destroy(t);
}

void test_table_load_empty_file(void) {
  fwd_table_t *t = table_create();
  FILE *f = file_with("");
  size_t bad = 99;
  TEST_ASSERT_TRUE(table_load(t, f, &bad));
  fclose(f);
  TEST_ASSERT_EQUAL_size_t(0, bad);
  TEST_ASSERT_EQUAL_size_t(0, table_count(t));
  table_destroy(t);
}

void test_table_load_bad_line_in_the_middle(void) {
  fwd_table_t *t = table_create();
  FILE *f = file_with("# a table with a mistake\n"
                      "10.0.0.0/8 direct eth0\n"
                      "11.0.0.0/8 direct eth1\n"
                      "12.0.0.0/8 nowhere eth2\n"
                      "13.0.0.0/8 direct eth3\n");
  size_t bad = 99;
  TEST_ASSERT_FALSE(table_load(t, f, &bad));
  fclose(f);
  TEST_ASSERT_EQUAL_size_t(4, bad);
  // The routes before the bad line stay; the ones after are never read
  TEST_ASSERT_EQUAL_size_t(2, table_count(t));
  TEST_ASSERT_NOT_NULL(table_lookup(t, ip("11.0.0.1")));
  TEST_ASSERT_NULL(table_lookup(t, ip("13.0.0.1")));
  table_destroy(t);
}

void test_table_load_bad_lines(void) {
  const char *files[] = {
      "10.0.0.1/8 direct eth0\n",                      // host bits set
      "10.0.0.0/8 direct\n",                           // missing device
      "10.0.0.0/8 direct eth0 extra\n",                // extra field
      "10.0.0.0/8 direct eth0\n10.0.0.0/8 direct eth1\n", // duplicate block
      "default 1.1.1.1 a\n0.0.0.0/0 2.2.2.2 b\n",      // default twice
  };
  const size_t lines[] = {1, 1, 1, 2, 2};
  for (size_t i = 0; i < sizeof files / sizeof files[0]; i++) {
    fwd_table_t *t = table_create();
    FILE *f = file_with(files[i]);
    size_t bad = 99;
    TEST_ASSERT_FALSE_MESSAGE(table_load(t, f, &bad), files[i]);
    TEST_ASSERT_EQUAL_size_t_MESSAGE(lines[i], bad, files[i]);
    fclose(f);
    table_destroy(t);
  }
}

void test_table_load_bad_line_null_out(void) {
  fwd_table_t *t = table_create();
  FILE *f = file_with("10.0.0.0/8 direct eth0\nbad\n");
  TEST_ASSERT_FALSE(table_load(t, f, NULL));
  fclose(f);
  TEST_ASSERT_EQUAL_size_t(1, table_count(t));
  table_destroy(t);

  t = table_create();
  f = file_with("10.0.0.0/8 direct eth0\n");
  TEST_ASSERT_TRUE(table_load(t, f, NULL));
  fclose(f);
  TEST_ASSERT_EQUAL_size_t(1, table_count(t));
  table_destroy(t);
}

void test_table_load_null_arguments(void) {
  fwd_table_t *t = table_create();
  FILE *f = file_with("10.0.0.0/8 direct eth0\n");
  size_t bad = 99;
  TEST_ASSERT_FALSE(table_load(NULL, f, &bad));
  TEST_ASSERT_EQUAL_size_t(0, bad);
  bad = 99;
  TEST_ASSERT_FALSE(table_load(t, NULL, &bad));
  TEST_ASSERT_EQUAL_size_t(0, bad);
  TEST_ASSERT_FALSE(table_load(NULL, NULL, NULL));
  fclose(f);
  TEST_ASSERT_EQUAL_size_t(0, table_count(t));
  table_destroy(t);
}

void test_table_load_unreadable_file(void) {
  // A stream opened only for writing can not be read from
  fwd_table_t *t = table_create();
  FILE *f = fopen("/dev/null", "w");
  TEST_ASSERT_NOT_NULL(f);
  size_t bad = 99;
  TEST_ASSERT_FALSE(table_load(t, f, &bad));
  TEST_ASSERT_EQUAL_size_t(0, bad);
  fclose(f);
  TEST_ASSERT_EQUAL_size_t(0, table_count(t));
  table_destroy(t);
}

void test_table_load_appends(void) {
  // A second load adds to what is already there
  fwd_table_t *t = table_create();
  FILE *f = file_with("10.0.0.0/8 direct eth0\n");
  TEST_ASSERT_TRUE(table_load(t, f, NULL));
  fclose(f);
  f = file_with("default 1.1.1.1 wan\n");
  TEST_ASSERT_TRUE(table_load(t, f, NULL));
  fclose(f);
  TEST_ASSERT_EQUAL_size_t(2, table_count(t));
  TEST_ASSERT_EQUAL_STRING("eth0", table_lookup(t, ip("10.0.0.1"))->dev);
  TEST_ASSERT_EQUAL_STRING("wan", table_lookup(t, ip("9.0.0.1"))->dev);
  table_destroy(t);
}

void test_table_load_long_line(void) {
  // Longer than any fixed buffer a parser might use
  char text[4096];
  memset(text, ' ', sizeof text);
  const char *r = "10.0.0.0/8 direct eth0";
  memcpy(text + 3000, r, strlen(r));
  text[sizeof text - 2] = '\n';
  text[sizeof text - 1] = '\0';
  fwd_table_t *t = table_create();
  FILE *f = file_with(text);
  TEST_ASSERT_TRUE(table_load(t, f, NULL));
  fclose(f);
  TEST_ASSERT_EQUAL_size_t(1, table_count(t));
  table_destroy(t);
}

int main(void) {
  UNITY_BEGIN();
  // Task 1
  RUN_TEST(test_ip_parse_valid);
  RUN_TEST(test_ip_parse_rejects_wrong_number_of_octets);
  RUN_TEST(test_ip_parse_rejects_bad_separators);
  RUN_TEST(test_ip_parse_rejects_out_of_range_octets);
  RUN_TEST(test_ip_parse_rejects_leading_zeros);
  RUN_TEST(test_ip_parse_rejects_junk);
  RUN_TEST(test_ip_parse_null);
  RUN_TEST(test_ip_format);
  RUN_TEST(test_ip_round_trip);
  RUN_TEST(test_cidr_parse_valid);
  RUN_TEST(test_cidr_parse_rejects_malformed);
  RUN_TEST(test_cidr_parse_null);
  RUN_TEST(test_cidr_format);
  RUN_TEST(test_cidr_round_trip);
  // Task 2
  RUN_TEST(test_cidr_mask);
  RUN_TEST(test_cidr_mask_every_prefix);
  RUN_TEST(test_onyx_subnet);
  RUN_TEST(test_cidr_network_and_broadcast);
  RUN_TEST(test_prefix_0);
  RUN_TEST(test_prefix_1);
  RUN_TEST(test_prefix_30);
  RUN_TEST(test_prefix_31);
  RUN_TEST(test_prefix_32);
  RUN_TEST(test_prefix_over_32_is_32);
  RUN_TEST(test_host_count_every_prefix);
  RUN_TEST(test_cidr_contains);
  RUN_TEST(test_cidr_is_network);
  RUN_TEST(test_cidr_subnet_split_24_into_4);
  RUN_TEST(test_cidr_subnet_into_1_is_itself);
  RUN_TEST(test_cidr_subnet_from_0);
  RUN_TEST(test_cidr_subnet_to_31_and_32);
  RUN_TEST(test_cidr_subnet_failures);
  RUN_TEST(test_cidr_subnet_covers_block);
  // Task 3
  RUN_TEST(test_route_parse_valid);
  RUN_TEST(test_route_parse_whitespace);
  RUN_TEST(test_route_parse_device_length);
  RUN_TEST(test_route_parse_rejects);
  RUN_TEST(test_table_create_destroy);
  RUN_TEST(test_table_add);
  RUN_TEST(test_table_add_rejects);
  RUN_TEST(test_table_add_prefix_over_32);
  RUN_TEST(test_table_add_unterminated_device);
  RUN_TEST(test_table_grows);
  RUN_TEST(test_lookup_longest_prefix_wins);
  RUN_TEST(test_lookup_order_does_not_matter);
  RUN_TEST(test_lookup_default_route);
  RUN_TEST(test_lookup_host_and_point_to_point_routes);
  RUN_TEST(test_table_load_example);
  RUN_TEST(test_table_load_comments_and_blank_lines);
  RUN_TEST(test_table_load_empty_file);
  RUN_TEST(test_table_load_bad_line_in_the_middle);
  RUN_TEST(test_table_load_bad_lines);
  RUN_TEST(test_table_load_bad_line_null_out);
  RUN_TEST(test_table_load_null_arguments);
  RUN_TEST(test_table_load_unreadable_file);
  RUN_TEST(test_table_load_appends);
  RUN_TEST(test_table_load_long_line);
  return UNITY_END();
}
