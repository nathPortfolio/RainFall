# Bonus 1

**Vulnerability:** Signed/unsigned integer overflow bypassing a bounds check.

## Walkthrough

The program reads `n = atoi(argv[1])` and checks `n <= 9` before doing
`memcpy(buf, argv[2], n * 4)` into a 40-byte buffer. Finally, if a local variable
equals `0x574f4c46` ("FLOW"), it runs `execl("/bin/sh", ...)`.

Two bugs combine:

1. `n` is **signed**, so a large negative value passes `n <= 9`.
2. `memcpy`'s size is **unsigned** (`size_t`). A negative `n * 4` wraps around to a
   small positive size.

With `n = -1073741813`, `n * 4` overflows to **44**. We then copy 44 bytes into the
40-byte `buf`, and the extra 4 bytes spill directly onto the variable checked against
`"FLOW"`. Set those 4 bytes to `FLOW` and the shell spawns.

## Exploit

```sh
printf 'id\ncat /home/user/bonus2/.pass\n' | ./bonus1 -1073741813 $(python -c "print 'A'*40+'FLOW'")
```

**Flag:** `579bd19263eb8655e4cf7b742d75edf8c38226925d78db8163506f5191825245`
