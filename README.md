# P3 - Subnetting and Forwarding

- Name: Landon Quaintance
- Email: LandonQuaintance@u.boisestate.edu
- Class: CS425-001

The lookup a router does on every packet: given a destination address and a
forwarding table, find the longest prefix that matches. Along the way it does
the CIDR arithmetic (masks, network and broadcast addresses, host ranges, and
splitting a block into equal subnets) with plain bit operations on 32-bit
addresses.

```bash
make all
./build/release/myapp info 132.178.227.11/25
./build/release/myapp split 192.168.1.0/24 4
./build/release/myapp lookup tables/example.txt 132.178.227.50 8.8.8.8 10.1.2.5 10.1.2.200
```

Run with no arguments to see the usage. Exit codes: 0 on success, 1 for a bad
command line or a malformed address (including a `split` of a block with host
bits set, or a count that is not a power of two), 2 when the table file can not
be opened or has a bad line, and 3 when an address matches no route. A `lookup`
always reports every address; if some were malformed and some unreachable it
exits 1. Errors go to stderr and name what was wrong, for example
`myapp: tables/bad.txt:4: not a valid route`.

## Design

The code is split the same way as the interface. `src/lab.c` holds every
function in `src/lab.h` and does no I/O except reading the `FILE *` handed to
`table_load()`, so all of it is unit tested directly. `src/main.c` is only the
command line: it parses the arguments, calls the library, and formats the
output and exit code.

**Parsing.** `ip_parse()` and `cidr_parse()` share two small helpers. One reads
a decimal number with an upper bound (255 for an octet, 32 for a prefix),
requires at least one digit, and rejects a leading zero unless the number is
just `0`. The other reads four of those separated by single periods. The bound
is checked after every digit, so a long run of digits can never overflow. Each
helper returns a pointer just past what it read, and the callers then insist on
exactly `'\0'` (for an address) or `'/'` and then `'\0'` (for a block). That is
how `1.2.3.4x`, ` 1.2.3.4`, `+1.2.3.4`, `1..2.3`, `010.0.0.1`, `1.2.3.4/024`
and `1.2.3.4/` are all rejected. Nothing uses `inet_aton()`, `sscanf()` or
`strtol()`.

**The mask, and /0.** Everything is built on `cidr_mask()`. The obvious
`0xFFFFFFFF << (32 - prefix)` shifts by 32 for a /0, which is undefined behavior
in C (and on x86 gives back `0xFFFFFFFF`, so the default route would match only
`0.0.0.0`). `cidr_mask()` returns 0 for a /0 before it ever shifts, so the
largest shift it does is 31. A prefix over 32 is clamped to 32 in one helper,
which every function uses, so they all agree on what such a block means. From
the mask, network is `addr & mask`, broadcast is `addr | ~mask`, containment is
`(x & mask) == (addr & mask)`, and a block is a network when `addr & ~mask` is
0. With a mask of 0, a /0 contains every address and its broadcast is
`255.255.255.255`, with no special case. Its host count is 2^32 - 2, and the
2^32 needs 33 bits, so `cidr_host_count()` does that arithmetic in `uint64_t`.

**/31 and /32.** These two do not follow the formula. A /31 is a point to point
link (RFC 3021), so both of its addresses are hosts: the first host is the
network address, the last host is the broadcast address, and the count is 2. A
/32 is a single host, so first host, last host, network and broadcast are all
the address itself, and the count is 1. `cidr_first_host()`, `cidr_last_host()`
and `cidr_host_count()` check for a prefix of 31 or more before applying the
usual "network + 1, broadcast - 1, 2^(32-p) - 2" rule.

**Splitting.** `cidr_subnet()` checks that the block is a network and that `n`
is a nonzero power of two (`n & (n - 1)` is 0), then counts the bits that `n`
borrows from the host part. If the new prefix would pass 32, or `i` is out of
range, it fails. Subnet `i` is `network + i * 2^(32 - new prefix)`, again in 64
bits, because splitting a /0 into 1 piece makes a block of 2^32 addresses. It
hands back one subnet at a time, so splitting `0.0.0.0/0` into 2^31 pieces uses
no extra memory.

**The forwarding table.** `struct fwd_table` is a dynamic array of `route_t`
with a count and a capacity. `table_add()` rejects a destination with host bits
set and a second route to the same block (same network address and prefix,
like `ip route add`), then doubles the array with `realloc()` when it is full.
If `realloc()` fails the old array is still valid, so the table is unchanged.
`table_destroy()` frees the array and the struct.

**Longest prefix match.** `table_lookup()` scans every route. Among the routes
whose block contains the destination, it keeps the one with the longest prefix,
replacing its current best only when it finds a strictly longer one. It never
stops at the first match, so the order the routes were added in can not change
the answer. Two different routes can not tie: two blocks with the same prefix
that both contain an address are the same block, and `table_add()` refuses
duplicates. The default route is just `0.0.0.0/0`, the shortest prefix there
is. It contains everything, so it wins only when nothing more specific does,
and it is never a special case. With no default route, an address outside
every block gets `NULL`, which `main.c` prints as `unreachable`. A linear scan
is O(n) per lookup, which is fine for a table this size. A binary trie would
make it at most 32 steps regardless of table size.

**Loading.** `route_parse()` trims leading and trailing whitespace, splits the
rest into exactly three fields on spaces and tabs, copies each into a buffer of
the largest valid size (so an overlong field is rejected rather than
truncated), and then parses them: `default` or a network in CIDR notation, then
`direct` or a dotted quad, then a device of 1 to 15 characters. It builds the
route in a local and copies it out only on success, so `*route` is untouched on
failure. `table_load()` reads with `getline()`, cuts each line at the first `#`,
skips lines that are then blank, and stops at the first line that
`route_parse()` or `table_add()` rejects, reporting its 1-based number. Every
exit path frees the `getline()` buffer, and the routes from earlier lines stay
in the table for the caller to free with `table_destroy()`. A stream error
returns false with `bad_line` set to 0.

## Testing

- `make check`: 57 Unity tests covering every function in `src/lab.h`. They
  include every malformed input listed in Task 1, plus signs, whitespace, hex,
  trailing periods and overlong digit runs. The boundaries tested are /0, /1,
  /30, /31, /32 and prefixes over 32, along with `0.0.0.0` and
  `255.255.255.255`. `cidr_mask()` is checked at every prefix and the host
  count at every prefix from /0 to /30. Splitting is tested from /0 (including
  2^31 pieces), down to /31 and /32, into 1, and with every failure reason.
  Lookup is tested with four nested routes where only the /25 is right,
  repeated with the same routes added in five different orders. The table
  tests also cover a default route added first and last, a table with no
  default route, the example table's lookups, a 1000-route table that forces
  several reallocations, duplicate blocks, and a table file with a bad line in
  the middle (the routes before it stay, the ones after are never read).
  `table_load()` is also tested on comments, blank lines, a missing final
  newline, an empty file, a 4 KB line, and an unreadable stream. Every table
  file in the tests comes from `tmpfile()`.
- `make report`: 100% line and branch coverage of `src/lab.c`. The only
  exclusion is the `realloc()` failure path in `table_add()`.
- `make leak` / `make leak-test`: clean under AddressSanitizer with leak
  detection on Linux. The command line's error paths were also run under the
  debug build: a bad route on line 5, a missing file, malformed and unreachable
  addresses mixed in one lookup, and every bad `split`. None of them leaked.
- Built with zero warnings on Onyx (gcc 11.5) and macOS (clang), and the
  `info`, `split` and `lookup` output was compared against the examples in the
  assignment.

## Known Bugs or Issues

None known. An address that matches no route is printed on stdout as
`<address> unreachable`, and the run exits 3. A `split` into a very large
count (for example `0.0.0.0/0` into 2147483648) is valid and prints every
subnet, which takes a long time and a lot of output, but no extra memory.

## Experience

TODO: Describe your experience with the project (struggles, breakthroughs, etc.).
