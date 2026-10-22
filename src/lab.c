#define _POSIX_C_SOURCE 200809L

#include "lab.h"
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

/** The routes live in one array that doubles in size as it fills. */
struct fwd_table
{
  route_t *routes;
  size_t count;
  size_t capacity;
};

/* ------------------------------------------------------------------------
 * Task 1 - Address parsing and formatting
 * --------------------------------------------------------------------- */

static bool is_digit(char c) { return c >= '0' && c <= '9'; }

static bool is_space(char c)
{
  return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\v' || c == '\f';
}

/**
 * Read a decimal number no greater than max from the start of text. At least
 * one digit is required, and a leading zero is only allowed on "0" itself.
 * Returns a pointer just past the last digit, or NULL if there is no valid
 * number there.
 */
static const char *parse_decimal(const char *text, uint32_t max, uint32_t *value)
{
  if (!is_digit(*text))
  {
    return NULL;
  }
  if (text[0] == '0' && is_digit(text[1]))
  {
    return NULL;
  }

  uint32_t v = 0;
  while (is_digit(*text))
  {
    v = v * 10 + (uint32_t)(*text - '0');
    if (v > max)
    {
      return NULL; // also stops v from ever overflowing
    }
    text++;
  }
  *value = v;
  return text;
}

/**
 * Read a dotted quad from the start of text. Returns a pointer just past it,
 * or NULL if text does not start with one.
 */
static const char *parse_quad(const char *text, uint32_t *addr)
{
  uint32_t result = 0;
  for (int i = 0; i < 4; i++)
  {
    if (i > 0)
    {
      if (*text != '.')
      {
        return NULL;
      }
      text++;
    }
    uint32_t octet;
    text = parse_decimal(text, 255, &octet);
    if (text == NULL)
    {
      return NULL;
    }
    result = (result << 8) | octet;
  }
  *addr = result;
  return text;
}

bool ip_parse(const char *text, uint32_t *addr)
{
  if (text == NULL || addr == NULL)
  {
    return false;
  }
  uint32_t a;
  const char *end = parse_quad(text, &a);
  if (end == NULL || *end != '\0')
  {
    return false;
  }
  *addr = a;
  return true;
}

void ip_format(uint32_t addr, char out[IP_STR_LEN])
{
  snprintf(out, IP_STR_LEN, "%u.%u.%u.%u", (addr >> 24) & 0xFFu, (addr >> 16) & 0xFFu,
           (addr >> 8) & 0xFFu, addr & 0xFFu);
}

bool cidr_parse(const char *text, cidr_t *block)
{
  if (text == NULL || block == NULL)
  {
    return false;
  }
  uint32_t a;
  const char *p = parse_quad(text, &a);
  if (p == NULL || *p != '/')
  {
    return false;
  }
  uint32_t prefix;
  p = parse_decimal(p + 1, 32, &prefix);
  if (p == NULL || *p != '\0')
  {
    return false;
  }
  block->addr = a;
  block->prefix = (uint8_t)prefix;
  return true;
}

/** A prefix over 32 is treated as 32 everywhere, as cidr_mask() specifies. */
static uint8_t clamp_prefix(uint8_t prefix) { return prefix > 32 ? 32 : prefix; }

void cidr_format(cidr_t block, char out[CIDR_STR_LEN])
{
  char ip[IP_STR_LEN];
  ip_format(block.addr, ip);
  snprintf(out, CIDR_STR_LEN, "%s/%u", ip, (unsigned)clamp_prefix(block.prefix));
}

/* ------------------------------------------------------------------------
 * Task 2 - Subnet arithmetic
 * --------------------------------------------------------------------- */

uint32_t cidr_mask(uint8_t prefix)
{
  prefix = clamp_prefix(prefix);
  if (prefix == 0)
  {
    return 0; // shifting by 32 would be undefined behavior
  }
  return UINT32_MAX << (32 - prefix);
}

uint32_t cidr_network(cidr_t block) { return block.addr & cidr_mask(block.prefix); }

uint32_t cidr_broadcast(cidr_t block) { return block.addr | ~cidr_mask(block.prefix); }

uint32_t cidr_first_host(cidr_t block)
{
  uint32_t network = cidr_network(block);
  return clamp_prefix(block.prefix) >= 31 ? network : network + 1;
}

uint32_t cidr_last_host(cidr_t block)
{
  uint32_t broadcast = cidr_broadcast(block);
  return clamp_prefix(block.prefix) >= 31 ? broadcast : broadcast - 1;
}

uint64_t cidr_host_count(cidr_t block)
{
  uint8_t prefix = clamp_prefix(block.prefix);
  if (prefix == 32)
  {
    return 1;
  }
  if (prefix == 31)
  {
    return 2;
  }
  return (UINT64_C(1) << (32 - prefix)) - 2;
}

bool cidr_contains(cidr_t block, uint32_t addr)
{
  uint32_t mask = cidr_mask(block.prefix);
  return (addr & mask) == (block.addr & mask);
}

bool cidr_is_network(cidr_t block) { return (block.addr & ~cidr_mask(block.prefix)) == 0; }

bool cidr_subnet(cidr_t block, uint32_t n, uint32_t i, cidr_t *out)
{
  if (out == NULL || !cidr_is_network(block))
  {
    return false;
  }
  if (n == 0 || (n & (n - 1)) != 0)
  {
    return false;
  }
  uint32_t bits = 0;
  while ((UINT32_C(1) << bits) < n)
  {
    bits++;
  }
  uint32_t prefix = clamp_prefix(block.prefix) + bits;
  if (prefix > 32 || i >= n)
  {
    return false;
  }
  // 64 bits because a /0 split into 1 is a block of 2^32 addresses
  uint64_t size = UINT64_C(1) << (32 - prefix);
  out->addr = (uint32_t)(block.addr + i * size);
  out->prefix = (uint8_t)prefix;
  return true;
}

/* ------------------------------------------------------------------------
 * Task 3 - Longest prefix match
 * --------------------------------------------------------------------- */

/**
 * Copy the next field of a route line into out, which holds size bytes
 * including the '\0'. Fields are separated by spaces and tabs. Returns a
 * pointer just past the field, or NULL if there is no field or it is too long.
 */
static const char *next_field(const char *p, const char *end, char *out, size_t size)
{
  while (p < end && (*p == ' ' || *p == '\t'))
  {
    p++;
  }
  size_t len = 0;
  while (p + len < end && p[len] != ' ' && p[len] != '\t')
  {
    len++;
  }
  if (len == 0 || len >= size)
  {
    return NULL;
  }
  memcpy(out, p, len);
  out[len] = '\0';
  return p + len;
}

bool route_parse(const char *line, route_t *route)
{
  if (line == NULL || route == NULL)
  {
    return false;
  }

  // Trim the leading and trailing whitespace, including the newline
  const char *start = line;
  while (is_space(*start))
  {
    start++;
  }
  const char *end = start + strlen(start);
  while (end > start && is_space(end[-1]))
  {
    end--;
  }

  char dest[CIDR_STR_LEN];
  char gateway[IP_STR_LEN];
  char dev[DEV_NAME_LEN];
  const char *p = next_field(start, end, dest, sizeof dest);
  if (p != NULL)
  {
    p = next_field(p, end, gateway, sizeof gateway);
  }
  if (p != NULL)
  {
    p = next_field(p, end, dev, sizeof dev);
  }
  if (p == NULL || p != end)
  {
    return false; // a field is missing, too long, or there is a fourth one
  }

  route_t r;
  memset(&r, 0, sizeof r);
  if (strcmp(dest, "default") == 0)
  {
    r.dest.addr = 0;
    r.dest.prefix = 0;
  }
  else if (!cidr_parse(dest, &r.dest) || !cidr_is_network(r.dest))
  {
    return false;
  }

  if (strcmp(gateway, "direct") == 0)
  {
    r.gateway = 0;
  }
  else if (!ip_parse(gateway, &r.gateway))
  {
    return false;
  }

  // Only spaces and tabs separate fields, so any other whitespace is in one
  for (const char *c = dev; *c != '\0'; c++)
  {
    if (is_space(*c))
    {
      return false;
    }
  }
  memcpy(r.dev, dev, strlen(dev) + 1);

  *route = r;
  return true;
}

fwd_table_t *table_create(void)
{
  fwd_table_t *table = calloc(1, sizeof *table);
  return table; // NULL if calloc failed
}

void table_destroy(fwd_table_t *table)
{
  if (table == NULL)
  {
    return;
  }
  free(table->routes);
  free(table);
}

size_t table_count(const fwd_table_t *table) { return table == NULL ? 0 : table->count; }

bool table_add(fwd_table_t *table, const route_t *route)
{
  if (table == NULL || route == NULL || !cidr_is_network(route->dest))
  {
    return false;
  }

  uint8_t prefix = clamp_prefix(route->dest.prefix);
  for (size_t i = 0; i < table->count; i++)
  {
    const cidr_t *have = &table->routes[i].dest;
    if (have->addr == route->dest.addr && clamp_prefix(have->prefix) == prefix)
    {
      return false; // same block, like ip route add's "File exists"
    }
  }

  if (table->count == table->capacity)
  {
    size_t capacity = table->capacity == 0 ? 8 : table->capacity * 2;
    route_t *grown = realloc(table->routes, capacity * sizeof *grown);
    if (grown == NULL) // GCOVR_EXCL_START
    {
      return false; // the old array is still valid and unchanged
    } // GCOVR_EXCL_STOP
    table->routes = grown;
    table->capacity = capacity;
  }

  route_t *slot = &table->routes[table->count];
  *slot = *route;
  slot->dev[DEV_NAME_LEN - 1] = '\0'; // in case the caller's name was not terminated
  table->count++;
  return true;
}

/** true if the line holds nothing but whitespace. */
static bool is_blank(const char *line)
{
  while (is_space(*line))
  {
    line++;
  }
  return *line == '\0';
}

bool table_load(fwd_table_t *table, FILE *in, size_t *bad_line)
{
  if (bad_line != NULL)
  {
    *bad_line = 0;
  }
  if (table == NULL || in == NULL)
  {
    return false;
  }

  char *line = NULL;
  size_t size = 0;
  size_t number = 0;
  bool ok = true;
  while (getline(&line, &size, in) != -1)
  {
    number++;
    char *comment = strchr(line, '#');
    if (comment != NULL)
    {
      *comment = '\0';
    }
    if (is_blank(line))
    {
      continue;
    }
    route_t route;
    if (!route_parse(line, &route) || !table_add(table, &route))
    {
      if (bad_line != NULL)
      {
        *bad_line = number;
      }
      ok = false;
      break;
    }
  }
  free(line);

  if (ok && ferror(in))
  {
    return false; // bad_line stays 0: the file could not be read
  }
  return ok;
}

const route_t *table_lookup(const fwd_table_t *table, uint32_t dest)
{
  if (table == NULL)
  {
    return NULL;
  }
  // Check every route, so the order they were added in can not matter
  const route_t *best = NULL;
  for (size_t i = 0; i < table->count; i++)
  {
    const route_t *r = &table->routes[i];
    if (cidr_contains(r->dest, dest) &&
        (best == NULL || clamp_prefix(r->dest.prefix) > clamp_prefix(best->dest.prefix)))
    {
      best = r;
    }
  }
  return best;
}
