---
layout: post
title: CSAW CTF Quals 2016 - deedeedee
modified:
categories: blog
excerpt: ""
tags: []
image:
  feature:
share: true
comments: true
date: 2016-09-19T21:38:29+08:00
---

# CSAW CTF Quals 2016 - deedeedee
>**Points:** 150   
**Category:** Reversing  
**Description**  
(I lost the description to this challenge)  
[deedeedee](/resources/files/csaw2016/rev/deedeedee)

---

This is a reversing challenge. Given a binary, our objective was to find the flag. I vaguely remember that the description of this challenge was something along the lines of being able to execute instructions at compile time.

We're given a 64-bit ELF.

{% highlight bash linenos %}
$ file deedeedee
deedeedee: ELF 64-bit LSB  executable, x86-64, version 1 (SYSV), dynamically linked (uses shared 
libs), for GNU/Linux 2.6.24, BuildID[sha1]=4fac9c863749015d039a3bf0a3a6c936f2f7eadd, not stripped
{% endhighlight %}

Running the binary in my CTF environment tells us that we have the encrypted flag, and that the flag was generated at compile time. 

{% highlight bash linenos %}
$ ./deedeedee
Your hexencoded, encrypted flag is: 676c60677a74326d716c6074325f6c6575347172316773616c6d686e665f68735e6773385e345e3377657379316e327d
I generated it at compile time. :)
Can you decrypt it for me?
{% endhighlight %}

The hexencoded flag decodes to ``gl`gzt2mql`t2_leu4qr1gsalmhnf_hs^gs8^4^3wesy1n2}``. Keep this in mind, we will need it later. You could use python to decode the hex encoded string or simply use any hex->text converter online.

### Analysis

Running `objdump -x` on the binary shows that there are many functions defined, and instincts tells me that at least one of these would contain the routine required to decrypt our flag. 

Doing a simple grep for `encrypt` finds the function we are searching for:

{% highlight bash linenos %}
$ objdump -x deedeedee | grep encrypt
000000000044cde0 g     F .text  000000000000158b              _D9deedeedee7encryptFNaNfAyaZAya
{% endhighlight %}

Note that the names are all mangled, but we can still roughly make out the meaning of the functions.

The disassembly for the function shows some kind of chained function calls where the result of one call is used as argument for the other call.

{% highlight bash linenos %}
gdb-peda$ disas _D9deedeedee7encryptFNaNfAyaZAya
Dump of assembler code for function _D9deedeedee7encryptFNaNfAyaZAya:
   0x000000000044cde0 <+0>:     push   rbp
   0x000000000044cde1 <+1>:     mov    rbp,rsp
   0x000000000044cde4 <+4>:     sub    rsp,0x10
   0x000000000044cde8 <+8>:     mov    QWORD PTR [rbp-0x10],rdi
   0x000000000044cdec <+12>:    mov    QWORD PTR [rbp-0x8],rsi
   0x000000000044cdf0 <+16>:    mov    rdx,QWORD PTR [rbp-0x8]
   0x000000000044cdf4 <+20>:    mov    rax,QWORD PTR [rbp-0x10]
   0x000000000044cdf8 <+24>:    mov    rdi,rax
   0x000000000044cdfb <+27>:    mov    rsi,rdx
   0x000000000044cdfe <+30>:    call   0x451470 <_D9deedeedee21__T3encVAyaa3_313131Z3encFNaNfAyaZAya>
   0x000000000044ce03 <+35>:    mov    rdi,rax
   0x000000000044ce06 <+38>:    mov    rsi,rdx
   0x000000000044ce09 <+41>:    call   0x458280 <_D9deedeedee21__T3encVAyaa3_323232Z3encFNaNfAyaZAya>
   0x000000000044ce0e <+46>:    mov    rdi,rax
   0x000000000044ce11 <+49>:    mov    rsi,rdx
   0x000000000044ce14 <+52>:    call   0x458358 <_D9deedeedee21__T3encVAyaa3_333333Z3encFNaNfAyaZAya>
   [** Truncated **]
   0x000000000044e348 <+5480>:  mov    rdi,rax
   0x000000000044e34b <+5483>:  mov    rsi,rdx
   0x000000000044e34e <+5486>:  call   0x472428 <_D9deedeedee33__T3encVAyaa9_343937343937343937Z3encFNaNfAyaZAya>
   0x000000000044e353 <+5491>:  mov    rdi,rax
   0x000000000044e356 <+5494>:  mov    rsi,rdx
   0x000000000044e359 <+5497>:  call   0x472500 <_D9deedeedee33__T3encVAyaa9_343938343938343938Z3encFNaNfAyaZAya>
   0x000000000044e35e <+5502>:  mov    rdi,rax
   0x000000000044e361 <+5505>:  mov    rsi,rdx
   0x000000000044e364 <+5508>:  call   0x4725d8 <_D9deedeedee33__T3encVAyaa9_343939343939343939Z3encFNaNfAyaZAya>
   0x000000000044e369 <+5513>:  leave
   0x000000000044e36a <+5514>:  ret
End of assembler dump.
{% endhighlight %}

What we can notice from the disassembly is:

1. Each function takes in two argument, registers $rdi and $rsi.
2. The function names are slightly different, first one has `313131` and second one has `323232` in it.

The next logical thing to do is to disassemble one of the function calls:

{% highlight bash linenos %}
gdb-peda$ disas _D9deedeedee21__T3encVAyaa3_313131Z3encFNaNfAyaZAya
Dump of assembler code for function _D9deedeedee21__T3encVAyaa3_313131Z3encFNaNfAyaZAya:
   0x0000000000451470 <+0>:     push   rbp
   0x0000000000451471 <+1>:     mov    rbp,rsp
   0x0000000000451474 <+4>:     sub    rsp,0xb0
   0x000000000045147b <+11>:    mov    QWORD PTR [rbp-0xa8],rbx
   0x0000000000451482 <+18>:    mov    QWORD PTR [rbp-0x10],rdi
   0x0000000000451486 <+22>:    mov    QWORD PTR [rbp-0x8],rsi
   [** Truncated **]
   0x00000000004514aa <+58>:    mov    edx,0x49fa5c
   [** Truncated **]
   0x000000000045150c <+156>:   xor    esi,DWORD PTR [rdx]
   0x000000000045150e <+158>:   movzx  ebx,BYTE PTR [rbp-0xa0]
   0x0000000000451515 <+165>:   xor    esi,ebx
   [** Truncated **]
   0x0000000000451543 <+211>:   leave
   0x0000000000451544 <+212>:   ret
End of assembler dump.
{% endhighlight %}

What I noticed is that the arguments provided is xor'ed with the string located at `0x49fa5c`, which is `0x31`. Remember the 0x313131 contained in the name of the function?

{% highlight bash linenos %}
gdb-peda$ x/xw0x49fa5c
0x49fa5c <_TMP75>:      0x00313131
{% endhighlight %}

Now with these, I have some idea of how the encryption is done (probably a chain of xors with some constant byte values, 0x31 in this case). We can further verify this by doing dynamic analysis.

We first set a breakpoint at main, and run the binary in gdb. We then jump to `0x000000000044CDE0`, which is the start of the encrypt function.

{% highlight bash linenos %}
gdb-peda$ b _D9deedeedee7encryptFNaNfAyaZAya
Breakpoint 2 at 0x44cde4
gdb-peda$ j _D9deedeedee7encryptFNaNfAyaZAya
Continuing at 0x44cde4.
{% endhighlight %}

Remember that the chain of function takes in two argument from register $rsi and $rdi, I assume that one of this register contains a pointer to the string we are encoding and the other pointer containing the len of the string.

With that assumption, we set the register to the correct values. We can do so by running the following gdb calls. We also set a breakpoint at the first xor instruction, so that we can verify the xor values.

{% highlight bash linenos %}
gdb-peda$ p strcpy($rsi, "222")
gdb-peda$ set $rdi=3
gdb-peda$ b *0x000000000045150c
Breakpoint 3 at 0x45150c
gdb-peda$ c
Continuing.
[----------------------------------registers-----------------------------------]
RAX: 0x7fffffffe390 --> 0x3200000031 ('1')
RBX: 0x7fffffffe368 --> 0x3
RCX: 0x7fffffffe390 --> 0x3200000031 ('1')
RDX: 0x7fffffffe394 --> 0x300000032
RSI: 0x31 ('1')
RDI: 0x7fffffffe2d0 --> 0x3200000031 ('1')
[** Truncated **]
=> 0x45150c <_D9deedeedee21__T3encVAyaa3_313131Z3encFNaNfAyaZAya+156>:
    xor    esi,DWORD PTR [rdx]
   0x45150e <_D9deedeedee21__T3encVAyaa3_313131Z3encFNaNfAyaZAya+158>:
    movzx  ebx,BYTE PTR [rbp-0xa0]
   0x451515 <_D9deedeedee21__T3encVAyaa3_313131Z3encFNaNfAyaZAya+165>:  xor    esi,ebx
[** Truncated **]
gdb-peda$
{% endhighlight %}

We see that the $ebx contains 0x3 which is the length we set at register $rdi as well. Thus, in this function, every byte in the input string is xor'ed with 0x31 as well as the length of the input string.

In python, the particular function would look something like the following

{% highlight python linenos %}
def enc313131(inputStr):
   length = len(inputStr)
   result = ""
   for character in inputStr:
      result += chr(ord(character) ^ 0x31 ^ length)
   return result
{% endhighlight %}


Now that we have confirmed our assumptions, the flag can be easily decrypted by running the same function with the flag and the length as input.

{% highlight bash linenos %}
gdb-peda$ b *0x000000000044E408
Breakpoint 1 at 0x44e408
gdb-peda$ r
[** truncated **]
=> 0x44e408 <_Dmain>:   push   rbp
[** truncated **]
gdb-peda$ p strcpy($rsi,"gl`gzt2mql`t2_leu4qr1gsalmhnf_hs^gs8^4^3wesy1n2}")
[** truncated **]
gdb-peda$ b *0x000000000044cde0
Breakpoint 2 at 0x44cde0
gdb-peda$ j *0x000000000044cde0
Continuing at 0x44cde0.
[** truncated **]
=> 0x44cde0 <_D9deedeedee7encryptFNaNfAyaZAya>: push   rbp
[** truncated **]
gdb-peda$ set $rdi=48
gdb-peda$ b *0x000000000044e36a
Breakpoint 3 at 0x44e36a
gdb-peda$ c
Continuing.
[** truncated **]
RDX: 0x7ffff7ef1c80 ("flag{t3mplat3_met4pr0gramming_is_gr8_4_3very0n3}")
[** truncated **]
{% endhighlight %}

And we have our flag!