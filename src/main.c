#include "lab.h"
#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef TEST
#define main main_exclude
#endif

/* Exit codes */
#define EXIT_USAGE 1       // bad command line or malformed address
#define EXIT_TABLE 2       // table file can not be opened or has a bad line
#define EXIT_UNREACHABLE 3 // an address matched no route

static void usage(FILE *out)
{
  fprintf(out, "Usage: myapp info <address>/<prefix>\n"
               "       myapp split <network>/<prefix> <count>\n"
               "       myapp lookup <table-file> <address>...\n");
}

static int cmd_info(const char *arg)
{
  cidr_t block;
  if (!cidr_parse(arg, &block))
  {
    fprintf(stderr, "myapp: %s: not a valid address/prefix\n", arg);
    return EXIT_USAGE;
  }

  char address[IP_STR_LEN], netmask[IP_STR_LEN], network[IP_STR_LEN];
  char broadcast[IP_STR_LEN], first[IP_STR_LEN], last[IP_STR_LEN];
  ip_format(block.addr, address);
  ip_format(cidr_mask(block.prefix), netmask);
  ip_format(cidr_network(block), network);
  ip_format(cidr_broadcast(block), broadcast);
  ip_format(cidr_first_host(block), first);
  ip_format(cidr_last_host(block), last);

  printf("address    %s\n", address);
  printf("prefix     /%u\n", (unsigned)block.prefix);
  printf("netmask    %s\n", netmask);
  printf("network    %s\n", network);
  printf("broadcast  %s\n", broadcast);
  printf("first host %s\n", first);
  printf("last host  %s\n", last);
  printf("hosts      %" PRIu64 "\n", cidr_host_count(block));
  return EXIT_SUCCESS;
}

/** Parse a subnet count: decimal digits only, no sign, no leading zero. */
static bool parse_count(const char *text, uint32_t *count)
{
  if (text[0] < '1' || text[0] > '9')
  {
    return false;
  }
  uint64_t v = 0;
  for (const char *p = text; *p != '\0'; p++)
  {
    if (*p < '0' || *p > '9')
    {
      return false;
    }
    v = v * 10 + (uint64_t)(*p - '0');
    if (v > UINT32_MAX)
    {
      return false;
    }
  }
  *count = (uint32_t)v;
  return true;
}

static int cmd_split(const char *block_arg, const char *count_arg)
{
  cidr_t block;
  if (!cidr_parse(block_arg, &block))
  {
    fprintf(stderr, "myapp: %s: not a valid network/prefix\n", block_arg);
    return EXIT_USAGE;
  }
  if (!cidr_is_network(block))
  {
    char network[CIDR_STR_LEN];
    cidr_format((cidr_t){cidr_network(block), block.prefix}, network);
    fprintf(stderr, "myapp: %s: host bits are set, so it is not a network (did you mean %s?)\n",
            block_arg, network);
    return EXIT_USAGE;
  }
  uint32_t n;
  if (!parse_count(count_arg, &n) || (n & (n - 1)) != 0)
  {
    fprintf(stderr, "myapp: %s: count must be a power of two from 1 up\n", count_arg);
    return EXIT_USAGE;
  }

  cidr_t subnet;
  if (!cidr_subnet(block, n, 0, &subnet))
  {
    fprintf(stderr, "myapp: %s can not be split into %s subnets: the prefix would pass /32\n",
            block_arg, count_arg);
    return EXIT_USAGE;
  }
  for (uint64_t i = 0; i < n; i++)
  {
    char text[CIDR_STR_LEN];
    cidr_subnet(block, n, (uint32_t)i, &subnet);
    cidr_format(subnet, text);
    printf("%s\n", text);
  }
  return EXIT_SUCCESS;
}

static int cmd_lookup(const char *path, int count, char *addresses[])
{
  FILE *in = fopen(path, "r");
  if (in == NULL)
  {
    fprintf(stderr, "myapp: %s: can not open: %s\n", path, strerror(errno));
    return EXIT_TABLE;
  }
  fwd_table_t *table = table_create();
  if (table == NULL)
  {
    fprintf(stderr, "myapp: out of memory\n");
    fclose(in);
    return EXIT_TABLE;
  }
  size_t bad_line;
  bool loaded = table_load(table, in, &bad_line);
  fclose(in);
  if (!loaded)
  {
    if (bad_line > 0)
    {
      fprintf(stderr, "myapp: %s:%zu: not a valid route\n", path, bad_line);
    }
    else
    {
      fprintf(stderr, "myapp: %s: could not be read\n", path);
    }
    table_destroy(table);
    return EXIT_TABLE;
  }

  bool malformed = false;
  bool unreachable = false;
  for (int i = 0; i < count; i++)
  {
    uint32_t dest;
    if (!ip_parse(addresses[i], &dest))
    {
      fprintf(stderr, "myapp: %s: not a valid address\n", addresses[i]);
      malformed = true;
      continue;
    }
    char text[IP_STR_LEN];
    ip_format(dest, text);
    const route_t *route = table_lookup(table, dest);
    if (route == NULL)
    {
      printf("%s unreachable\n", text);
      unreachable = true;
    }
    else if (route->gateway != 0)
    {
      char gateway[IP_STR_LEN];
      ip_format(route->gateway, gateway);
      printf("%s via %s dev %s\n", text, gateway, route->dev);
    }
    else
    {
      printf("%s dev %s\n", text, route->dev);
    }
  }
  table_destroy(table);

  if (malformed)
  {
    return EXIT_USAGE;
  }
  return unreachable ? EXIT_UNREACHABLE : EXIT_SUCCESS;
}

int main(int argc, char *argv[])
{
  if (argc == 1)
  {
    usage(stdout);
    return EXIT_SUCCESS;
  }

  const char *command = argv[1];
  if (strcmp(command, "info") == 0 && argc == 3)
  {
    return cmd_info(argv[2]);
  }
  if (strcmp(command, "split") == 0 && argc == 4)
  {
    return cmd_split(argv[2], argv[3]);
  }
  if (strcmp(command, "lookup") == 0 && argc >= 4)
  {
    return cmd_lookup(argv[2], argc - 3, &argv[3]);
  }

  if (strcmp(command, "info") == 0 || strcmp(command, "split") == 0 ||
      strcmp(command, "lookup") == 0)
  {
    fprintf(stderr, "myapp: wrong number of arguments for %s\n", command);
  }
  else
  {
    fprintf(stderr, "myapp: unknown command '%s'\n", command);
  }
  usage(stderr);
  return EXIT_USAGE;
}
