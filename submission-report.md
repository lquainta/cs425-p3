# Submission Report

- Submission generated at 10/22/2026 at 03:36:34

- Machine info: Linux runnervm8k3b6 6.17.0-1022-azure #22-Ubuntu SMP Mon Jul 27 17:24:03 UTC 2026 x86_64 x86_64 x86_64 GNU/Linux

## Note to Students

Please read this report carefully before submission.
Ensure that all sections are complete and accurate.
Look for any errors in the build or test outputs.
If you find any issues, correct them before submitting.
Post any questions on the class discussion board for help.


---

## README

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
prints one line per address in the order given, and an address that matches no
route prints just `unreachable` on stdout. It always reports every address; if
some were malformed and some unreachable it exits 1. Errors go to stderr and name what was wrong, for example
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

None known. An address that matches no route prints only `unreachable` on
stdout, without the address, and the run exits 3. In a lookup of several
addresses, its line's position tells which one it was. A malformed address is
reported on stderr instead and prints nothing on stdout, so the stdout lines
then no longer line up one for one with the arguments. A `split` into a very large
count (for example `0.0.0.0/0` into 2147483648) is valid and prints every
subnet, which takes a long time and a lot of output, but no extra memory.

## Experience

Yeah this project was pretty fun. I feel like I am learning a lot about how to use AI for development. It is super fun 
and I just like to see how many tokens I can burn at the end of the day. I mostly want to see what the cap is for my Claude Pro
subscription, but haven't managed to hit that yet. Honestly this project was kind of easy and I got it done in about 10 minutes,
thanks to my boy Claude.

---


## Build Output

This section was generated by running `make all` in the project root directory.

```bash
make[1]: Entering directory '/home/runner/work/cs425-p3/cs425-p3'
mkdir -p build/debug
cc -g -O0 -DDEBUG -fno-omit-frame-pointer -fsanitize=address -c src/lab.c -o build/debug/lab.c.o
mkdir -p build/debug
cc -g -O0 -DDEBUG -fno-omit-frame-pointer -fsanitize=address -c src/main.c -o build/debug/main.c.o
cc -g -O0 -DDEBUG -fno-omit-frame-pointer -fsanitize=address build/debug/lab.c.o build/debug/main.c.o -o build/debug/myapp_d -fsanitize=address
make[1]: Leaving directory '/home/runner/work/cs425-p3/cs425-p3'
make[1]: Entering directory '/home/runner/work/cs425-p3/cs425-p3'
mkdir -p build/release
cc -Wall -Wextra -O2 -fPIE -MMD -MP -Wformat -Wformat=2 -Wconversion -Wsign-conversion -Wimplicit-fallthrough -fstack-protector-strong -Werror=format-security -Werror=implicit -Werror=incompatible-pointer-types -Werror=int-conversion -c src/lab.c -o build/release/lab.c.o
mkdir -p build/release
cc -Wall -Wextra -O2 -fPIE -MMD -MP -Wformat -Wformat=2 -Wconversion -Wsign-conversion -Wimplicit-fallthrough -fstack-protector-strong -Werror=format-security -Werror=implicit -Werror=incompatible-pointer-types -Werror=int-conversion -c src/main.c -o build/release/main.c.o
cc -Wall -Wextra -O2 -fPIE -MMD -MP -Wformat -Wformat=2 -Wconversion -Wsign-conversion -Wimplicit-fallthrough -fstack-protector-strong -Werror=format-security -Werror=implicit -Werror=incompatible-pointer-types -Werror=int-conversion build/release/lab.c.o build/release/main.c.o -o build/release/myapp 
make[1]: Leaving directory '/home/runner/work/cs425-p3/cs425-p3'
make[1]: Entering directory '/home/runner/work/cs425-p3/cs425-p3'
mkdir -p build/tests
cc -g -O0 -DTEST -fprofile-arcs -ftest-coverage -c src/lab.c -o build/tests/lab.c.o
mkdir -p build/tests
cc -g -O0 -DTEST -fprofile-arcs -ftest-coverage -c src/main.c -o build/tests/main.c.o
mkdir -p build/tests/
cc -g -O0 -DTEST -fprofile-arcs -ftest-coverage -c tests/lab-test.c -o build/tests/lab-test.c.o
mkdir -p build/tests/harness/
cc -g -O0 -DTEST -fprofile-arcs -ftest-coverage -c tests/harness/unity.c -o build/tests/harness/unity.c.o
cc -g -O0 -DTEST -fprofile-arcs -ftest-coverage build/tests/lab.c.o build/tests/main.c.o build/tests/lab-test.c.o build/tests/harness/unity.c.o -o build/tests/myapp_t -fprofile-arcs -ftest-coverage
make[1]: Leaving directory '/home/runner/work/cs425-p3/cs425-p3'
make[1]: Entering directory '/home/runner/work/cs425-p3/cs425-p3'
mkdir -p build/debug-test
cc -g -O0 -DDEBUG -DTEST -fno-omit-frame-pointer -fsanitize=address -c src/lab.c -o build/debug-test/lab.c.o
mkdir -p build/debug-test
cc -g -O0 -DDEBUG -DTEST -fno-omit-frame-pointer -fsanitize=address -c src/main.c -o build/debug-test/main.c.o
mkdir -p build/debug-test/
cc -g -O0 -DDEBUG -DTEST -fno-omit-frame-pointer -fsanitize=address -c tests/lab-test.c -o build/debug-test/lab-test.c.o
mkdir -p build/debug-test/harness/
cc -g -O0 -DDEBUG -DTEST -fno-omit-frame-pointer -fsanitize=address -c tests/harness/unity.c -o build/debug-test/harness/unity.c.o
cc -g -O0 -DDEBUG -DTEST -fno-omit-frame-pointer -fsanitize=address build/debug-test/lab.c.o build/debug-test/main.c.o build/debug-test/lab-test.c.o build/debug-test/harness/unity.c.o -o build/debug-test/myapp_td -fsanitize=address
make[1]: Leaving directory '/home/runner/work/cs425-p3/cs425-p3'
Builds completed. You can run the application with: ./build/release/myapp
You can run the debug build with: ./build/debug/myapp_d
You can run the test build with: ./build/tests/myapp_t
You can run the debug-test build with: ./build/debug-test/myapp_td
```

---

## Coverage Report

This section was generated by running `make report` in the project root directory.

```bash
tests/lab-test.c:990:test_ip_parse_valid:PASS
tests/lab-test.c:991:test_ip_parse_rejects_wrong_number_of_octets:PASS
tests/lab-test.c:992:test_ip_parse_rejects_bad_separators:PASS
tests/lab-test.c:993:test_ip_parse_rejects_out_of_range_octets:PASS
tests/lab-test.c:994:test_ip_parse_rejects_leading_zeros:PASS
tests/lab-test.c:995:test_ip_parse_rejects_junk:PASS
tests/lab-test.c:996:test_ip_parse_null:PASS
tests/lab-test.c:997:test_ip_format:PASS
tests/lab-test.c:998:test_ip_round_trip:PASS
tests/lab-test.c:999:test_cidr_parse_valid:PASS
tests/lab-test.c:1000:test_cidr_parse_rejects_malformed:PASS
tests/lab-test.c:1001:test_cidr_parse_null:PASS
tests/lab-test.c:1002:test_cidr_format:PASS
tests/lab-test.c:1003:test_cidr_round_trip:PASS
tests/lab-test.c:1005:test_cidr_mask:PASS
tests/lab-test.c:1006:test_cidr_mask_every_prefix:PASS
tests/lab-test.c:1007:test_onyx_subnet:PASS
tests/lab-test.c:1008:test_cidr_network_and_broadcast:PASS
tests/lab-test.c:1009:test_prefix_0:PASS
tests/lab-test.c:1010:test_prefix_1:PASS
tests/lab-test.c:1011:test_prefix_30:PASS
tests/lab-test.c:1012:test_prefix_31:PASS
tests/lab-test.c:1013:test_prefix_32:PASS
tests/lab-test.c:1014:test_prefix_over_32_is_32:PASS
tests/lab-test.c:1015:test_host_count_every_prefix:PASS
tests/lab-test.c:1016:test_cidr_contains:PASS
tests/lab-test.c:1017:test_cidr_is_network:PASS
tests/lab-test.c:1018:test_cidr_subnet_split_24_into_4:PASS
tests/lab-test.c:1019:test_cidr_subnet_into_1_is_itself:PASS
tests/lab-test.c:1020:test_cidr_subnet_from_0:PASS
tests/lab-test.c:1021:test_cidr_subnet_to_31_and_32:PASS
tests/lab-test.c:1022:test_cidr_subnet_failures:PASS
tests/lab-test.c:1023:test_cidr_subnet_covers_block:PASS
tests/lab-test.c:1025:test_route_parse_valid:PASS
tests/lab-test.c:1026:test_route_parse_whitespace:PASS
tests/lab-test.c:1027:test_route_parse_device_length:PASS
tests/lab-test.c:1028:test_route_parse_rejects:PASS
tests/lab-test.c:1029:test_table_create_destroy:PASS
tests/lab-test.c:1030:test_table_add:PASS
tests/lab-test.c:1031:test_table_add_rejects:PASS
tests/lab-test.c:1032:test_table_add_prefix_over_32:PASS
tests/lab-test.c:1033:test_table_add_unterminated_device:PASS
tests/lab-test.c:1034:test_table_grows:PASS
tests/lab-test.c:1035:test_lookup_longest_prefix_wins:PASS
tests/lab-test.c:1036:test_lookup_order_does_not_matter:PASS
tests/lab-test.c:1037:test_lookup_default_route:PASS
tests/lab-test.c:1038:test_lookup_host_and_point_to_point_routes:PASS
tests/lab-test.c:1039:test_table_load_example:PASS
tests/lab-test.c:1040:test_table_load_comments_and_blank_lines:PASS
tests/lab-test.c:1041:test_table_load_empty_file:PASS
tests/lab-test.c:1042:test_table_load_bad_line_in_the_middle:PASS
tests/lab-test.c:1043:test_table_load_bad_lines:PASS
tests/lab-test.c:1044:test_table_load_bad_line_null_out:PASS
tests/lab-test.c:1045:test_table_load_null_arguments:PASS
tests/lab-test.c:1046:test_table_load_unreadable_file:PASS
tests/lab-test.c:1047:test_table_load_appends:PASS
tests/lab-test.c:1048:test_table_load_long_line:PASS

-----------------------
57 Tests 0 Failures 0 Ignored 
OK
./build/tests/myapp_t
tests/lab-test.c:990:test_ip_parse_valid:PASS
tests/lab-test.c:991:test_ip_parse_rejects_wrong_number_of_octets:PASS
tests/lab-test.c:992:test_ip_parse_rejects_bad_separators:PASS
tests/lab-test.c:993:test_ip_parse_rejects_out_of_range_octets:PASS
tests/lab-test.c:994:test_ip_parse_rejects_leading_zeros:PASS
tests/lab-test.c:995:test_ip_parse_rejects_junk:PASS
tests/lab-test.c:996:test_ip_parse_null:PASS
tests/lab-test.c:997:test_ip_format:PASS
tests/lab-test.c:998:test_ip_round_trip:PASS
tests/lab-test.c:999:test_cidr_parse_valid:PASS
tests/lab-test.c:1000:test_cidr_parse_rejects_malformed:PASS
tests/lab-test.c:1001:test_cidr_parse_null:PASS
tests/lab-test.c:1002:test_cidr_format:PASS
tests/lab-test.c:1003:test_cidr_round_trip:PASS
tests/lab-test.c:1005:test_cidr_mask:PASS
tests/lab-test.c:1006:test_cidr_mask_every_prefix:PASS
tests/lab-test.c:1007:test_onyx_subnet:PASS
tests/lab-test.c:1008:test_cidr_network_and_broadcast:PASS
tests/lab-test.c:1009:test_prefix_0:PASS
tests/lab-test.c:1010:test_prefix_1:PASS
tests/lab-test.c:1011:test_prefix_30:PASS
tests/lab-test.c:1012:test_prefix_31:PASS
tests/lab-test.c:1013:test_prefix_32:PASS
tests/lab-test.c:1014:test_prefix_over_32_is_32:PASS
tests/lab-test.c:1015:test_host_count_every_prefix:PASS
tests/lab-test.c:1016:test_cidr_contains:PASS
tests/lab-test.c:1017:test_cidr_is_network:PASS
tests/lab-test.c:1018:test_cidr_subnet_split_24_into_4:PASS
tests/lab-test.c:1019:test_cidr_subnet_into_1_is_itself:PASS
tests/lab-test.c:1020:test_cidr_subnet_from_0:PASS
tests/lab-test.c:1021:test_cidr_subnet_to_31_and_32:PASS
tests/lab-test.c:1022:test_cidr_subnet_failures:PASS
tests/lab-test.c:1023:test_cidr_subnet_covers_block:PASS
tests/lab-test.c:1025:test_route_parse_valid:PASS
tests/lab-test.c:1026:test_route_parse_whitespace:PASS
tests/lab-test.c:1027:test_route_parse_device_length:PASS
tests/lab-test.c:1028:test_route_parse_rejects:PASS
tests/lab-test.c:1029:test_table_create_destroy:PASS
tests/lab-test.c:1030:test_table_add:PASS
tests/lab-test.c:1031:test_table_add_rejects:PASS
tests/lab-test.c:1032:test_table_add_prefix_over_32:PASS
tests/lab-test.c:1033:test_table_add_unterminated_device:PASS
tests/lab-test.c:1034:test_table_grows:PASS
tests/lab-test.c:1035:test_lookup_longest_prefix_wins:PASS
tests/lab-test.c:1036:test_lookup_order_does_not_matter:PASS
tests/lab-test.c:1037:test_lookup_default_route:PASS
tests/lab-test.c:1038:test_lookup_host_and_point_to_point_routes:PASS
tests/lab-test.c:1039:test_table_load_example:PASS
tests/lab-test.c:1040:test_table_load_comments_and_blank_lines:PASS
tests/lab-test.c:1041:test_table_load_empty_file:PASS
tests/lab-test.c:1042:test_table_load_bad_line_in_the_middle:PASS
tests/lab-test.c:1043:test_table_load_bad_lines:PASS
tests/lab-test.c:1044:test_table_load_bad_line_null_out:PASS
tests/lab-test.c:1045:test_table_load_null_arguments:PASS
tests/lab-test.c:1046:test_table_load_unreadable_file:PASS
tests/lab-test.c:1047:test_table_load_appends:PASS
tests/lab-test.c:1048:test_table_load_long_line:PASS

-----------------------
57 Tests 0 Failures 0 Ignored 
OK
mkdir -p ./build/report/html
mkdir -p ./build/report/txt
gcovr -r . --html --html-details --exclude-directories build/tests/harness --exclude '.*main\.c$' --exclude '.*test\.c$' -o ./build/report/html/coverage_report.html
gcovr -r . --txt                 --exclude-directories build/tests/harness --exclude '.*main\.c$' --exclude '.*test\.c$'
------------------------------------------------------------------------------
                           GCC Code Coverage Report
Directory: .
------------------------------------------------------------------------------
File                                         Lines     Exec  Cover   Missing
------------------------------------------------------------------------------
src/lab.c                                      212      212   100%
------------------------------------------------------------------------------
TOTAL                                          212      212   100%
------------------------------------------------------------------------------
```

---

## Address Sanitizer Report

This section was generated by running `make leak-test` in the project root directory.

```bash
tests/lab-test.c:990:test_ip_parse_valid:PASS
tests/lab-test.c:991:test_ip_parse_rejects_wrong_number_of_octets:PASS
tests/lab-test.c:992:test_ip_parse_rejects_bad_separators:PASS
tests/lab-test.c:993:test_ip_parse_rejects_out_of_range_octets:PASS
tests/lab-test.c:994:test_ip_parse_rejects_leading_zeros:PASS
tests/lab-test.c:995:test_ip_parse_rejects_junk:PASS
tests/lab-test.c:996:test_ip_parse_null:PASS
tests/lab-test.c:997:test_ip_format:PASS
tests/lab-test.c:998:test_ip_round_trip:PASS
tests/lab-test.c:999:test_cidr_parse_valid:PASS
tests/lab-test.c:1000:test_cidr_parse_rejects_malformed:PASS
tests/lab-test.c:1001:test_cidr_parse_null:PASS
tests/lab-test.c:1002:test_cidr_format:PASS
tests/lab-test.c:1003:test_cidr_round_trip:PASS
tests/lab-test.c:1005:test_cidr_mask:PASS
tests/lab-test.c:1006:test_cidr_mask_every_prefix:PASS
tests/lab-test.c:1007:test_onyx_subnet:PASS
tests/lab-test.c:1008:test_cidr_network_and_broadcast:PASS
tests/lab-test.c:1009:test_prefix_0:PASS
tests/lab-test.c:1010:test_prefix_1:PASS
tests/lab-test.c:1011:test_prefix_30:PASS
tests/lab-test.c:1012:test_prefix_31:PASS
tests/lab-test.c:1013:test_prefix_32:PASS
tests/lab-test.c:1014:test_prefix_over_32_is_32:PASS
tests/lab-test.c:1015:test_host_count_every_prefix:PASS
tests/lab-test.c:1016:test_cidr_contains:PASS
tests/lab-test.c:1017:test_cidr_is_network:PASS
tests/lab-test.c:1018:test_cidr_subnet_split_24_into_4:PASS
tests/lab-test.c:1019:test_cidr_subnet_into_1_is_itself:PASS
tests/lab-test.c:1020:test_cidr_subnet_from_0:PASS
tests/lab-test.c:1021:test_cidr_subnet_to_31_and_32:PASS
tests/lab-test.c:1022:test_cidr_subnet_failures:PASS
tests/lab-test.c:1023:test_cidr_subnet_covers_block:PASS
tests/lab-test.c:1025:test_route_parse_valid:PASS
tests/lab-test.c:1026:test_route_parse_whitespace:PASS
tests/lab-test.c:1027:test_route_parse_device_length:PASS
tests/lab-test.c:1028:test_route_parse_rejects:PASS
tests/lab-test.c:1029:test_table_create_destroy:PASS
tests/lab-test.c:1030:test_table_add:PASS
tests/lab-test.c:1031:test_table_add_rejects:PASS
tests/lab-test.c:1032:test_table_add_prefix_over_32:PASS
tests/lab-test.c:1033:test_table_add_unterminated_device:PASS
tests/lab-test.c:1034:test_table_grows:PASS
tests/lab-test.c:1035:test_lookup_longest_prefix_wins:PASS
tests/lab-test.c:1036:test_lookup_order_does_not_matter:PASS
tests/lab-test.c:1037:test_lookup_default_route:PASS
tests/lab-test.c:1038:test_lookup_host_and_point_to_point_routes:PASS
tests/lab-test.c:1039:test_table_load_example:PASS
tests/lab-test.c:1040:test_table_load_comments_and_blank_lines:PASS
tests/lab-test.c:1041:test_table_load_empty_file:PASS
tests/lab-test.c:1042:test_table_load_bad_line_in_the_middle:PASS
tests/lab-test.c:1043:test_table_load_bad_lines:PASS
tests/lab-test.c:1044:test_table_load_bad_line_null_out:PASS
tests/lab-test.c:1045:test_table_load_null_arguments:PASS
tests/lab-test.c:1046:test_table_load_unreadable_file:PASS
tests/lab-test.c:1047:test_table_load_appends:PASS
tests/lab-test.c:1048:test_table_load_long_line:PASS

-----------------------
57 Tests 0 Failures 0 Ignored 
OK
```

---

## Src Files
### lab.c

```c

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
  // The prefix is written by hand: at most 2 digits, which snprintf can not
  // be told, so gcc would warn that "%u" might not fit
  ip_format(block.addr, out);
  size_t len = strlen(out);
  uint8_t prefix = clamp_prefix(block.prefix);
  out[len++] = '/';
  if (prefix >= 10)
  {
    out[len++] = (char)('0' + prefix / 10);
  }
  out[len++] = (char)('0' + prefix % 10);
  out[len] = '\0';
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

```

### lab.h

```c

#ifndef LAB_H
#define LAB_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

/*
 * Every address in this file is a uint32_t in host byte order, so the first
 * octet of 192.168.1.10 is the most significant byte: 0xC0A8010A.
 */

/** Room for the longest dotted quad, "255.255.255.255", and its '\0'. */
#define IP_STR_LEN 16

/** Room for the longest CIDR string, "255.255.255.255/32", and its '\0'. */
#define CIDR_STR_LEN 19

/** Room for an interface name; IFNAMSIZ on Linux, including the '\0'. */
#define DEV_NAME_LEN 16

/** An address block in CIDR notation: an address and a prefix length. */
typedef struct {
  uint32_t addr;  /**< any address in the block, host byte order */
  uint8_t prefix; /**< 0 to 32 */
} cidr_t;

/** One entry in a forwarding table. */
typedef struct {
  cidr_t dest;            /**< destination block; host bits must be zero */
  uint32_t gateway;       /**< next hop, or 0 when the block is directly connected */
  char dev[DEV_NAME_LEN]; /**< outgoing interface, for example "eth0" */
} route_t;

/** A forwarding table. Its layout is private to lab.c. */
typedef struct fwd_table fwd_table_t;

/* ------------------------------------------------------------------------
 * Task 1 - Address parsing and formatting
 * --------------------------------------------------------------------- */

/**
 * @brief Parse a dotted quad such as "192.168.1.10".
 *
 * Exactly four decimal octets from 0 to 255 separated by single periods, with
 * nothing before, between or after them. An octet with a leading zero ("010")
 * is rejected, because inet_aton() reads it as octal and that is never what a
 * person typing it meant.
 *
 * @param text The string to parse.
 * @param addr Where the address is stored on success; untouched on failure.
 * @return true if text is a valid dotted quad, false otherwise (including NULL).
 */
bool ip_parse(const char *text, uint32_t *addr);

/**
 * @brief Format an address as a dotted quad.
 * @param addr The address, host byte order.
 * @param out A buffer of at least IP_STR_LEN bytes.
 */
void ip_format(uint32_t addr, char out[IP_STR_LEN]);

/**
 * @brief Parse a block in CIDR notation such as "192.168.1.0/24".
 *
 * The address follows the rules of ip_parse() and the prefix is a decimal
 * number from 0 to 32 with no leading zero. The slash and the prefix are
 * required. Host bits may be set ("132.178.227.11/25" is an interface
 * address), so use cidr_is_network() when they must not be.
 *
 * @param text The string to parse.
 * @param block Where the block is stored on success; untouched on failure.
 * @return true if text is valid CIDR notation, false otherwise (including NULL).
 */
bool cidr_parse(const char *text, cidr_t *block);

/**
 * @brief Format a block as "a.b.c.d/p", using the address exactly as stored.
 *
 * A prefix over 32 is written as 32, the way cidr_mask() treats it.
 *
 * @param block The block.
 * @param out A buffer of at least CIDR_STR_LEN bytes.
 */
void cidr_format(cidr_t block, char out[CIDR_STR_LEN]);

/* ------------------------------------------------------------------------
 * Task 2 - Subnet arithmetic
 * --------------------------------------------------------------------- */

/**
 * @brief The subnet mask for a prefix length: /24 is 255.255.255.0.
 *
 * Careful with /0. Shifting a 32 bit value by 32 is undefined behavior in C.
 *
 * @param prefix 0 to 32; anything larger is treated as 32.
 * @return The mask, host byte order.
 */
uint32_t cidr_mask(uint8_t prefix);

/** @brief The lowest address in the block: the address with the host bits cleared. */
uint32_t cidr_network(cidr_t block);

/** @brief The highest address in the block: the address with the host bits set. */
uint32_t cidr_broadcast(cidr_t block);

/**
 * @brief The first address that can be given to a host.
 *
 * For /0 to /30 that is the network address plus one. A /31 is a point to
 * point link (RFC 3021) where both addresses are usable, and a /32 is a single
 * host, so for those two the first host is the network address.
 */
uint32_t cidr_first_host(cidr_t block);

/**
 * @brief The last address that can be given to a host.
 *
 * The broadcast address minus one for /0 to /30, and the broadcast address
 * itself for /31 and /32 (see cidr_first_host()).
 */
uint32_t cidr_last_host(cidr_t block);

/**
 * @brief How many addresses in the block can be given to hosts.
 *
 * 2^(32 - prefix) - 2 for /0 to /30, 2 for /31, and 1 for /32. For a /0 the
 * 2^32 in that formula needs 33 bits, more than a uint32_t holds, which is why
 * this returns a uint64_t.
 */
uint64_t cidr_host_count(cidr_t block);

/** @brief true if addr falls inside the block. */
bool cidr_contains(cidr_t block, uint32_t addr);

/** @brief true if the block's host bits are all zero, so it names a network. */
bool cidr_is_network(cidr_t block);

/**
 * @brief The i-th of n equally sized subnets of a block.
 *
 * Splitting a /24 into 4 gives four /26 blocks, and subnet 0 is the lowest.
 * Equal sizes are only possible when n is a power of two, and the new prefix
 * can not pass 32.
 *
 * @param block The block to split; it must be a network (cidr_is_network()).
 * @param n How many subnets, a power of two from 1 up.
 * @param i Which subnet, 0 to n - 1.
 * @param out Where the subnet is stored on success; untouched on failure.
 * @return false if out is NULL, the block is not a network, n is not a power
 *         of two, the split would need a prefix longer than 32, or i is out of
 *         range.
 */
bool cidr_subnet(cidr_t block, uint32_t n, uint32_t i, cidr_t *out);

/* ------------------------------------------------------------------------
 * Task 3 - Longest prefix match
 * --------------------------------------------------------------------- */

/**
 * @brief Parse one line of a forwarding table file.
 *
 * A line is three fields separated by spaces or tabs:
 *
 *     <destination> <gateway> <device>
 *
 * The destination is a block in CIDR notation with no host bits set, or the
 * word "default" for 0.0.0.0/0. The gateway is a dotted quad, or the word
 * "direct" for a directly connected block (stored as 0). The device is 1 to
 * DEV_NAME_LEN - 1 characters. Leading and trailing whitespace, including a
 * trailing newline, is ignored. Comments are not handled here.
 *
 * @param line The line.
 * @param route Where the route is stored on success; untouched on failure.
 * @return true if the line is a valid route, false otherwise (including NULL).
 */
bool route_parse(const char *line, route_t *route);

/**
 * @brief Create an empty forwarding table.
 * @return The table, which the caller frees with table_destroy(), or NULL if
 *         memory could not be allocated.
 */
fwd_table_t *table_create(void);

/** @brief Free a table and everything in it. NULL is allowed and does nothing. */
void table_destroy(fwd_table_t *table);

/** @brief The number of routes in the table; 0 for NULL. */
size_t table_count(const fwd_table_t *table);

/**
 * @brief Add a copy of a route to the table, growing it as needed.
 * @return false if either argument is NULL, the destination has host bits
 *         set, the table already holds a route to the same block, or memory
 *         could not be allocated. The table is unchanged on failure.
 */
bool table_add(fwd_table_t *table, const route_t *route);

/**
 * @brief Read a forwarding table file and add every route in it.
 *
 * Everything from a '#' to the end of a line is a comment, and a line that is
 * blank once the comment is removed is skipped. Every other line must be a
 * valid route (route_parse()) that table_add() accepts.
 *
 * @param table The table to add to.
 * @param in The open file to read.
 * @param bad_line If not NULL, set to the 1-based number of the first line
 *        that failed, or 0 if the arguments were NULL or the file could not
 *        be read.
 * @return true if every line loaded. On false, routes from the lines before
 *         the bad one stay in the table.
 */
bool table_load(fwd_table_t *table, FILE *in, size_t *bad_line);

/**
 * @brief Longest prefix match: the route whose block contains dest and has the
 *        longest prefix.
 *
 * A default route (0.0.0.0/0) matches everything, so it is chosen only when
 * nothing more specific does. The order the routes were added in does not
 * matter.
 *
 * @return The matching route, which stays owned by the table, or NULL if no
 *         route matches (or table is NULL).
 */
const route_t *table_lookup(const fwd_table_t *table, uint32_t dest);

#endif // LAB_H

```

### main.c

```c

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
      printf("unreachable\n");
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

```

## Tests Files
### lab-test.c

```c

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

```

## Scripts Files
Report generated on 10/22/2026 at 03:36:36


---

## End of Report

SHA-256 Hash of the report: 29a0d34531c177d41d8909768c8deb2136b31cd4d65cd4048814c66f553108ff

Do not edit the generated report. Any changes will be reported as academic dishonesty

---
## GitHub Info
- GitHub repo name: lquainta/cs425-p3
- The repository visibility is public.
- The workflow was triggered by lquainta
