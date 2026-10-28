# Level 0

**Vulnerability:** Hardcoded argument check.

## Walkthrough

`main` runs `atoi(argv[1])` and compares the result to `0x1a7`. If they match, it
drops privileges to its own euid/egid and runs `/bin/sh` via `execv`. Otherwise it
prints an error.

No overflow needed — we just supply the expected number.

```
0x1a7 = 423   (printf "%d\n" 0x1a7)
```

## Exploit

```sh
./level0 423
cat /home/user/level1/.pass
```

**Flag:** `1fe8a524fa4bec01ca4ea2a869af2a02260d4a7d5fe7e7c24d8617e6dca12d3a`
