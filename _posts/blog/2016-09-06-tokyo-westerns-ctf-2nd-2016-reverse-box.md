---
layout: post
title: Tokyo Westerns CTF 2nd 2016 - Reverse Box
modified:
categories: blog
excerpt: ""
tags: []
image:
  feature:
share: true
comments: true
date: 2016-09-06T11:29:51+08:00
---

# Tokyo Westerns / MMA CTF 2nd 2016 - Reverse Box
>**Points:** 50
**Category:** Reversing  
**Description**  
$ ./reverse_box ${FLAG}  
95eeaf95ef94234999582f722f492f72b19a7aaf72e6e776b57aee722fe77ab5ad9aaeb156729676ae7a236d99b1df4a  
[reverse_box.7z](/resources/files/tokyowesterns/reverse_box.7z)

---

This was a reversing warmup challenge for TWCTF 2016. I've read many write ups on this, but most of them did it differently from how I solved it, and many of their solutions seems to be more efficient than mine.

Given a 32-bit ELF binary and an output derived from the binary with the flag as input, the objective would be to determine the flag using the output values.

### Solution

The main function does nothing much other than to call a function that generates the S-box for the cipher.

{% highlight c linenos %}
  generate_S_Box(&buffer);
  for ( i = 0; i < strlen(argv[1]); ++i )
    printf("%02x", *((_BYTE *)&buffer[argv[1][i]]));
  putchar(10);
{% endhighlight %}

The generate_S_Box function starts by picking a random integer in the range of 0-255, and the rest of the function executes based on this random value. It didn't occur to me that I could simply generate all possible 256 values at this point using gdb/unicorn engine (like what other solutions are doing), so I reversed the entire function into Python.

{% highlight python linenoes %}
ror = lambda val, r_bits, max_bits: \
    ((val & (2**max_bits-1)) >> r_bits%max_bits) | \
    (val << (max_bits-(r_bits%max_bits)) & (2**max_bits-1))

all_s_boxes = {}
for randomValue in range(256):
  results = [0 for i in range(256)]
  position_index = 3;
  some_value = 1;
  while position_index != 1:
    # Used to generate some_value
    v1 = 2 * some_value ^ some_value & 0xff
    v2 = (v1 ^ v1 * 4) &0xff
    v3 = (v2 ^ v2 * 16) & 0xff
    if ( v3 < 128 ):
      v5 = 0;
    else: 
      v5 = 9;
    some_value = (v3 ^ v5) & 0xff;

    factor1 = some_value & 0xff
    factor2 = some_value ^ randomValue
    factor1_rotate_7bits = ror(factor1, 7,8)
    factor1_rotate_6bits = ror(factor1, 6,8)
    factor1_rotate_5bits = ror(factor1, 5,8)
    factor1_rotate_4bits = ror(factor1,4,8)
    result = factor2 ^ factor1_rotate_7bits ^ factor1_rotate_6bits ^ factor1_rotate_5bits ^ factor1_rotate_4bits

    results[position_index] = (result & 0xff)

    some_value = factor1
    v2 = (position_index ^ (2 * position_index));
    if position_index < 128:
      v3 = 0;
    else:
      v3 = 27;
    position_index = (v2 ^ v3) & 0xff
  all_s_boxes[randomValue] = results

startingFlag = "TWCTF"
startingTarget = "\x95\xee\xaf\x95\xef"
sbox_to_use = None

for key,sbox in all_s_boxes.items():
  for index,char in enumerate(startingFlag):
    if sbox[ord(char)] == ord(startingTarget[index]):
      sbox_to_use = sbox
      print "Found sbox at random value %d" % key
      break

target = "95eeaf95ef94234999582f722f492f72b19a7aaf72e6e776b57aee722fe77ab5ad9aaeb156729676ae7a236d99b1df4a"
print ''.join([chr(sbox_to_use.index(ord(i))) for i in target.decode('hex')])
{% endhighlight %}

Since we knew that the flag starts with `TWCTF`, we could make use of this information to determine the correct s-box to use in order to obtain the rest of the flag.

Running this script gives us the flag:
{% highlight bash linenos %}
→ python samples-1/test.py
Found sbox at random value 214
TWCTF{5UBS717U710N_C1PH3R_W17H_R4ND0M123D_5-B0X}
{% endhighlight %}
