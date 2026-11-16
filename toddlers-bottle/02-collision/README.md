# collision
**Tier**: toddlers-bottle  
**Points:** 3pts  
**Vulnerability:** [CWE-843: Access of Resource Using Incompatible Type](https://cwe.mitre.org/data/definitions/843.html)  
**Concepts:**  Endianness, Type Casting, Raw Byte Injection  
**Date:** 2026-11-16  

> Daddy told me about cool MD5 hash collision today.  
> I wanna do something like that too!  
> [collision - pwnable.kr](https://pwnable.kr/play/2)

## 1. Recon

The provided source code (`col.c`) contains two functions: `main` and 
`check_password`. Let us start by analyzing the `main` function and 
highlighting relevant details.

```c 
unsigned long hashcode = 0x21DD09EC;
int main(int argc, char* argv[]){
    // ...
	if(strlen(argv[1]) != 20){
		printf("passcode length should be 20 bytes\n");
        // fail
	}

	if (hashcode == check_password( argv[1] )) {
		// pass
	}
    // fail
}
```

The snippet above is a simplified view of the `main` function. To summarize,
the program requires the first argument to be exactly 20 bytes. Once that 
condition is met, it passes our input to the `check_password` function, whose
result is compared against the hardcoded `hashcode` variable. If the hashcode
matches the resulting value, the flag will be captured, otherwise, we will be
led to a failure path.

```c
unsigned long check_password(const char* p) {
	int* ip = (int*)p;
	int res = 0;
	for (int i = 0; i < 5; i++)
		res += ip[i];

	return res;
}
```

For readability's sake, I have made a few syntactic changes to the source code,
but its logic stays the same. The snippet above is the `check_password` 
function, which was used earlier by the `main` function. First, remember that 
the 20-byte input is passed to this function as variable `p`. Second, observe
how the function casts our input `p` into an integer pointer `ip`. Finally, it 
runs a loop which iterates through indices 0 to 5 of variable `ip`, with each
value being added to `res` whose initial value is 0.

In C, a standard `int` commonly uses 4 bytes of memory[^w3-c-dtypes]. Since the algorithm
treats our 20-byte string as an array of integers, it reads our string by chunks
of 4 bytes. 

```
01 02 03 04 05 06 07 08 09 10 11 12 13 14 15 16 17 18 19 20
|---------------------------------------------------------|
                       20-byte char*
```

To understand better, the visual shown above is how our string is stored in 
memory.

```
01 02 03 04 05 06 07 08 09 10 11 12 13 14 15 16 17 18 19 20
|---------| |---------| |---------| |---------| |---------|
   int 1       int 2       int 3       int 4       int 5
               20-byte char* read as integers           
```

Now, this visual shows how our string is read as integers. Again, since
a standard `int` takes up 4 bytes, it groups our 20-byte string into 
chunks of 4 bytes.

Since we're looking at the byte representation (base 256), the value of an
integer is evaluated by multiplying each byte with its corresponding positional 
weight in base-256 space[^w3-hexadecimals].

From the code snippet earlier, we see that the `hashcode` variable is defined
as the hexadecimal `0x21DD09EC`. Afterwards, we see in the `main` function that
the `hashcode` variable must equal to the result of our argument passed into the 
`check_password` function. As such, we deduce that we must pass a 20-byte string
as an argument such that its resulting value must equal to the hexadecimal 
`0x21DD09EC` when ran through the `check_password` function.

## 2. Exploit
### 2.1. Calculating the value

Remember, our main goal is to pass a 20-byte string that must equal to 
`0x21DD09EC` when ran through `check_password`. 

Since our 20-byte string is grouped into chunks of 4 bytes, we will have a total
of 5 chunks.

First, we must determine what the value of each chunk should be. `0x21DD09EC` 
divided by `0x5` yields `0x6C5CEC8` with a remainder of `0x4`. Therefore, to 
reconstruct the value `0x21DD09EC`, we distribute it across our 5 chunks with
the value `0x6C5CEC8`. Since we have a remainder of `0x4`, we need to add this
to the last chunk, therefore our 5th chunk has the value `0x6C5CECC`.

```
0x06 0xC5 0xCE 0xC8 0x06 0xC5 0xCE 0xC8 0x06 0xC5 0xCE 0xC8 0x06 0xC5 0xCE 0xC8 0x06 0xC5 0xCE 0xCC
|-----------------| |-----------------| |-----------------| |-----------------| |-----------------| 
       int 1               int 2               int 3               int 4               int 5         
```

To visualize, here is our resulting byte stream in the same format as the one
provided earlier.

### 2.2. Constructing the payload

Now that we have the values in place, we move on to constructing the payload.

First, we need to learn about memory order. Computers have two kinds of memory
order, also known as its endianness. In simpler terms, this determines the order
of how bytes are arranged in memory. This comes in two primary forms: 

1. Big-endian / Most Significant Bit, where the first byte is the largest
2. Little-endian / Least Significant Bit, where the first byte is the smallest

Big-endian makes most sense to people as it is read from left to right, however,
almost all modern systems use little-endian, which is read from right to left.

```
0x21 0xDD 0x09 0xEC
|-----------------|
     Big-endian

0xEC 0x09 0xDD 0x21
|-----------------|
   Little-endian
```

Shown above is an example of how our hashcode `0x21DD09EC` is encoded in both
endian forms. As one might observe, little-endian is simply the opposite order
of big-endian and vice versa. While their order differs, they still yield the 
same values.

```bash
$ file col
col: ELF 32-bit LSB pie executable, Intel i386, version 1 (SYSV)...
```

By checking the binary's metadata through the `file` utility, we see that it has
`LSB` in its output, indicating that it is made for little-endian systems. As
such, we must encode our payload in little-endian order.

```
0xC8 0xCE 0xC5 0x06 0xC8 0xCE 0xC5 0x06 0xC8 0xCE 0xC5 0x06 0xC8 0xCE 0xC5 0x06 0xCC 0xCE 0xC5 0x06 
|-----------------| |-----------------| |-----------------| |-----------------| |-----------------| 
       int 1               int 2               int 3               int 4               int 5         
```

Above is our payload encoded in little-endian order. What lies next is finding
a way to pass raw bytes as a string to our binary. 

To achieve this, we can make use of hexadecimal escape notations paired with
either the `echo` or `printf` utility, which follow the format `\xHH` where `HH`
is our hexadecimal value[^posix-xbd-5]. 

The following command above prints out raw bytes in little-endian order to the 
standard output:
```bash
printf "\xC8\xCE\xC5\x06\xC8\xCE\xC5\x06\xC8\xCE\xC5\x06\xC8\xCE\xC5\x06\xCC\xCE\xC5\x06"
```

### 2.3. Injecting the payload

To use the payload as an argument to the binary file, we utilize command 
substitution[^posix-xcu-2-6-3].

Thus, we capture the flag with this command:
```bash
./col $(printf "\xC8\xCE\xC5\x06\xC8\xCE\xC5\x06\xC8\xCE\xC5\x06\xC8\xCE\xC5\x06\xCC\xCE\xC5\x06")
```

## 3. References

[^w3-c-dtypes]: [W3Schools - C Data Types](https://www.w3schools.com/c/c_data_types.php)  
[^w3-hexadecimals]: [W3Schools - Hexadecimal Numbers in Programming](https://www.w3schools.com/programming/prog_hexadecimal_numbers.php)  
[^res-raw-bytes]: [Reverse Engineering Stack Exchange - What are some ways to pass raw bytes to a program via the Linux terminal?](https://reverseengineering.stackexchange.com/questions/24755/what-are-some-ways-to-pass-raw-bytes-to-a-program-via-the-linux-terminal])  
[^posix-xbd-5]: [POSIX.1-2024 XBD - Section 5](https://pubs.opengroup.org/onlinepubs/9799919799/basedefs/V1_chap05.html)  
[^posix-xcu-2-6-3]: [POSIX.1-2024 XCU - Section 2.6.3: Command Substitution](https://pubs.opengroup.org/onlinepubs/9799919799/utilities/V3_chap02.html#tag_19_06_03)    
