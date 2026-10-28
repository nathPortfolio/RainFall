# Level 8

**Vulnerability:** Use-after-free / heap layout confusion between two globals.

## Walkthrough

The program loops over four commands, tracking two global pointers `auth`
(`0x8049aac`) and `service` (`0x8049ab0`):

- `auth <string>` → `malloc(4)` then `strcpy(auth, <string>)`
- `reset` → `free(auth)`
- `service <string>` → `service = strdup(<string>)`
- `login` → if `*(auth + 0x20) != 0`, runs `system("/bin/sh")`

`login` checks a byte 0x20 past `auth`. Since `auth` only reserves a tiny chunk, a
following `service` allocation lands in that region, so its data makes
`*(auth + 0x20)` non-zero — passing the check.

Entering `auth ` (with a trailing space, so the stored string is non-empty) then a
`service` string arranges the heap so `login` succeeds.

## Exploit

```
./level8
auth
service AAAA
login
$ cat /home/user/level9/.pass
```

**Flag:** `c542e581c5ba5162a85f767996e3247ed619ef6c6f7b76a59435545dc6259f8a`
