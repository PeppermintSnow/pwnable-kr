# fd
**Tier**: toddlers-bottle  
**Points:** 1pt  
**Vulnerability:** [CWE-20: Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html)  
**Concepts:** File descriptors  
**Date:** 2026-11-13

> Mommy! what is a file descriptor in Linux?  
> [fd - pwnable.kr](https://pwnable.kr/play/1)

## 1. Recon

Based on the analysis of the provided source code (`fd.c`), it can be seen 
that the program is reading from an arbitrary file descriptor.

```c
char buf[32];
int main(int argc, char* argv[], char* envp[]) {
    // ...
    int fd = atoi( argv[1] ) - 0x1234;
    int len = 0;
    len = read(fd, buf, 32);
    if (!strcmp("LETMEWIN\n", buf)) {
        // pass
    }
    // fail
}
```

In UNIX and UNIX-like systems, a file descriptor (`fd`) is a per-process, 
non-negative integer that acts as a handle for I/O and control operations on an
open file. Three special values are reserved for the standard file descriptors 
[^posix-xbd-3-141]:

- **0**: Standard Input, where programs usually take their input from.
- **1**: Standard Output, where programs usually write output to.
- **2**: Standard Error, where diagnostic messages are usually written to.

Processes read from the standard input, write to the standard output, and
report to the standard error by default. Custom streams such as process-opened 
files, sockets, etc. are assigned the lowest available file descriptor
[^posix-xsh-2-6].

As seen in the snippet earlier, the `read` function attempts to read `n` bytes 
from the file descriptor [^man-read]. As such, we can say that the 
vulnerability of the program lies in reading the user-defined file descriptor.

With these definitions in mind, we surmise that the program does the following:
1. Takes a user-defined integer
2. Defines a file descriptor ID by subtracting `0x1234` to the integer
3. Reads 32 bytes from the file descriptor and saves to the buffer
4. Checks if the value read is `LETMEWIN`

Therefore, our target here is to have the program read from a file descriptor
that has the string `LETMEWIN` written into it.

## 2. Exploit
### 2.1. Standard Input Exploit

As defined in the previous section, programs take input from the standard 
input. Therefore, our first step is to get the program to read from the
standard input, which is 0.

Recall that the file descriptor in the program is derived from the input 
integer minus the hexadecimal `0x1234`.
```c 
int fd = atoi( argv[1] ) - 0x1234;
```

`0x1234` in decimal is `4660`, therefore we pass in `4660` as an argument to
our program. This way, the `fd` variable evaluates to `0`, which is later used
by the program to read 32 bytes from.
```c
len = read(fd, buf, 32);
```

With that in mind, we craft the command used to have the program read
from the standard input.
```bash
$ ./fd 4660
```

Relevant to this exploit is the UNIX pipeline, which is a mechanism that 
connects the standard output of a command to the standard input of the next
command[^posix-xcu-2-9-2]. This takes the format:
```bash
command1 [ | command2 ...]
```

This way, we can prepend a command that prints the string `LETMEWIN` to the 
standard output, and pipe it to our program which reads from the standard input.

Thus, we capture the flag through the following command:
```bash
$ echo "LETMEWIN" | ./fd 4660
```

The first part `echo "LETMEWIN"` writes the string `LETMEWIN` to the 
standard output. By utilizing the pipeline mechanism, its standard output now
connects to the standard input of the second command `./fd 4660`. Like so, the 
program reads the `LETMEWIN` from the previous command.

### 2.2. String Formatting Alternative

Building upon the previous section, we can also utilize the UNIX `printf` 
utility to skip the manual conversion of `0x1234` to decimal.

The `printf` utility writes values according to the provided format. This way,
we can make use of the format specifier `%d` to print the hexadecimal value 
`0x1234` as a decimal[^posix-xcu-3-printf]:
```bash 
$ printf "%d" 0x1234
```

We can then make use of command substitution, which evaluates the output of 
commands enclosed in `$(...)` and uses its value in-place[^posix-xcu-2-6-3]:
```bash 
$ echo "LETMEWIN" | ./fd $(printf "%d" 0x1234)
```

## 3. References

[^man-read]: [Linux man page - read(3)](https://linux.die.net/man/3/read)  
[^posix-xbd-3-141]: [POSIX.1-2024 XBD - Section 3.141: File Descriptor](https://pubs.opengroup.org/onlinepubs/9799919799/xbd.html#tag_03_141)  
[^posix-xcu-2-6-3]: [POSIX.1-2024 XCU - Section 2.6.3: Command Substitution](https://pubs.opengroup.org/onlinepubs/9799919799/utilities/V3_chap02.html#tag_19_06_03)  
[^posix-xcu-2-9-2]: [POSIX.1-2024 XCU - Section 2.9.2: Pipelines](https://pubs.opengroup.org/onlinepubs/9799919799/utilities/V3_chap02.html#tag_19_09_02)  
[^posix-xcu-3-printf]: [POSIX.1-2024 XCU - Section 3: Utilities - printf](https://pubs.opengroup.org/onlinepubs/9799919799/utilities/printf.html)  
[^posix-xsh-2-6]: [POSIX.1-2024 XSH - Section 2.6: File Descriptor Allocation](https://pubs.opengroup.org/onlinepubs/9799919799/functions/V2_chap02.html#tag_16_06)
