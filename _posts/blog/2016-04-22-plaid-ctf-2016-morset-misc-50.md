---
layout: post
title: Plaid CTF 2016 - Morset (Misc 50)
modified:
categories: blog
excerpt: ""
tags: []
image:
  feature:
share: true
comments: true
date: 2016-04-22T14:23:18+08:00
---

# Plaid CTF 2016 - Morset
>**Points:** 50  
**Category:** Misc  
**Description**  
A mysterious signal… can you decode it? Running at morset.pwning.xxx:11821

---

After connecting to the service, you'll receive some data that looks like morse code. If you enter some reply, you'll receive more morse code that looks like a response. I also found out that if you send some morse code back, you'll get a different response from if you send non-morse code characters, which seem to signify that the response is important for getting the flag.

Initially I couldn't determine the encoding of the messages, not until bo787 mentioned that it could be base36 that I realize it is base36-encoded.

# Solution

Connecting to `morset.pwning.xxx:11821` gives us:

{% highlight bash linenos %}
→ nc morset.pwning.xxx 11821
-.... ----. --- . .... ...- ...-- ...- .---- - ...- -.- -.-. .- .- ---.. ..- .-- --. ....- .-. -... .. -.-- .-.. -. --. ---.. - . -- --.- ....- -... ---.. .- ----- .- ...-- .--- ..- -. .---- ...- -..- .--- .--. -..- .-.. ----. --.. -.-- ...-- --.. . ----. .-- - --.. ....- .-.. -.. -.-. ----- . ..- .. -.... .. - ...- .-- -. ----. -.. .---- -.- -. .---- .-. -.- .... -.- .--. -- ..- .... --.. ----- ....- --. ...- -. ----. ...- .. ..--- -. .--. .--- .... ....- -.-- ...- -..- -.... ..- .- --.- --... --..
{% endhighlight %}

I then use a simple python script to encode/decode the morse code, to give:
{% highlight bash linenos %}
69OEHV3V1TVKCAA8UWG4RBIYLNG8TEMQ4B8A0A3JUN1VXJPXL9ZY3ZE9WTZ4LDC0EUI6ITVWN9D1KN1RKHKPMUHZ04GVN9VI2NPJH4YVX6UAQ7Z
{% endhighlight %}

This is encoded with base36 encoding, we can decode with python easily by using `int(a,36)` on it and then decoding with hex.
{% highlight bash linenos %}
>>> a = '69OEHV3V1TVKCAA8UWG4RBIYLNG8TEMQ4B8A0A3JUN1VXJPXL9ZY3ZE9WTZ4LDC0EUI6ITVWN9D1KN1RKHKPMUHZ04GVN9VI2NPJH4YVX6UAQ7Z'
>>> ("0"+hex(int(a,36))[2:-1]).decode('hex')
"\n ,=|=.\n(XXXXX)\n |   |\n \\   /\n  `+'\nWhat is the SHA256(Acorn3548096305)?"
{% endhighlight %}

So we can see that the response we need to provide is the answer to `SHA256(Acorn3548096305)`.

I wrote a python script to automate the entire process + encode the answer back to base36 + morse code before replying the service and getting the flag.

{% highlight python linenos %}
import sys
from pwn import *
context(arch = 'i386', os = 'linux')

def base36encode(number):
    if not isinstance(number, (int, long)):
        raise TypeError('number must be an integer')
    if number < 0:
        raise ValueError('number must be positive')

    alphabet, base36 = ['0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ', '']

    while number:
        number, i = divmod(number, 36)
        base36 = alphabet[i] + base36

    return base36 or alphabet[0]


morseAlphabet ={'A': '.-',     'B': '-...',   'C': '-.-.', 
        'D': '-..',    'E': '.',      'F': '..-.',
        'G': '--.',    'H': '....',   'I': '..',
        'J': '.---',   'K': '-.-',    'L': '.-..',
        'M': '--',     'N': '-.',     'O': '---',
        'P': '.--.',   'Q': '--.-',   'R': '.-.',
        'S': '...',    'T': '-',      'U': '..-',
        'V': '...-',   'W': '.--',    'X': '-..-',
        'Y': '-.--',   'Z': '--..',
        
        '0': '-----',  '1': '.----',  '2': '..---',
        '3': '...--',  '4': '....-',  '5': '.....',
        '6': '-....',  '7': '--...',  '8': '---..',
        '9': '----.' 
        }
    

inverseMorseAlphabet=dict((v,k) for (k,v) in morseAlphabet.items())

# parse a morse code string positionInString is the starting point for decoding
def decodeMorse(code, positionInString = 0):
    
    if positionInString < len(code):
        morseLetter = ""
        for key,char in enumerate(code[positionInString:]):
            if char == " ":
                positionInString = key + positionInString + 1
                letter = inverseMorseAlphabet[morseLetter]
                return letter + decodeMorse(code, positionInString)
            
            else:
                morseLetter += char
    else:
        return ""
    
#encode a message in morse code, spaces between words are represented by '/'
def encodeToMorse(message):
    encodedMessage = ""
    for char in message[:]:
        encodedMessage += morseAlphabet[char.upper()] + " "
            
    return encodedMessage

r = remote('morset.pwning.xxx', 11821)
challenge = r.recvline();
challenge = challenge.strip()+" "
challenge = decodeMorse(challenge);
challenge = "0"+hex(int(challenge,36))[2:]
challenge = challenge.decode('hex')
print challenge
index = challenge.index('6(')
import hashlib
response = hashlib.sha256(challenge[index+2:-2]).digest().encode('hex')
response = base36encode(int(str(response).encode('hex'),16))
print "SENDING"
r.sendline(encodeToMorse(response))
print hex(int(decodeMorse(r.recvline().strip()+" "),36))[2:].decode('hex');
{% endhighlight %}

Running the script gives us the flag:
{% highlight bash linenos %}
→ python Morset_getFlag.py
[+] Opening connection to morset.pwning.xxx on port 11821: Done

 ,).
((|))
 ``'
What is the SHA256(Pumpkin4202429674)?
SENDING
Nice! Here's a flag for you: PCTF{c0c0c0nutBaze_4__d4ys}.
[*] Closed connection to morset.pwning.xxx port 11821
{% endhighlight %}

And yay! we got the flag: ***PCTF{c0c0c0nutBaze_4__d4ys}***.

Unfortunately I was busy with school and did not manage to play much or to solve other challenges.
