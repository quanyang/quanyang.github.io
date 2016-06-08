---
layout: post
title: ALICTF 2016 - ColorOverflow (Reversing 100)
modified:
categories: blog
excerpt: ""
tags: []
image:
  feature:
share: true
comments: true
date: 2016-06-06T21:24:20+02:00
---

# ALICTF 2016 - ColorOverflow
>**Points:** 100
**Category:** Reversing  
**Description**  
ctf=Capture The traFfic? ([attachment](/resources/files/alictf/ColorOverflow_6c305d0795155a3fefbd47a4515fe06b.pcap))
HINT: port 5555

---

I only looked at this challenge after some time and by the time I started looking at it, quite a few teams have solved it already, and they've also given additional hint to look at **port 5555**.

The packet capture provided has quite a bit of HTTP traffic as well as traffic on port 5555. If you are familiar with Android debugging, port 5555 is often use for adb traffic. Looking at the conversation it is obvious that an apk is uploaded and installed on the device.

![](/resources/images/alictf/adb_traffic.png)

Using a python script with scapy, we can easily obtain the apk from the packet capture.

{% highlight python linenos %}
#!/usr/bin/env python
# Copyright (c) 2105 Josh Dosis
import base64
from scapy.all import * 
packets=rdpcap("a.pcap")
fp = file("ColorOverflow.apk","wb")
ranges = [(610,637),(641,908),(912,1178),(1183,1274)]
for start,end in ranges:
    for i in range(start,end+1):
        packet = packets[i]
        if TCP in packet and packet.sport == 33946:
            if packet[IP].dst == "10.0.2.15" and Raw in packet[TCP]:
                if i == 610:
                    fp.write(packet[TCP][Raw].load[32:])
                elif i == start:
                    fp.write(packet[TCP][Raw].load[24:])
                else:
                    out = packet[TCP][Raw].load
                    if "DATA" in out:
                        offset = out.find("DATA")
                        out = out[:offset] + out[offset+8:]
                    fp.write(out)
fp.close()
{% endhighlight %}

The APK file can be obtain [here](/resources/files/alictf/ColorOverflow.apk) if you're interested to take a look.

The APK application appears to be a game and it seems that it might be a real application.
After decompiling the APK with apktool, we see that within the assets folder, there is a HTML file with a github link to the [original game](http://github.com/TodorBalabanov/ColorsOverflow).

Comparing the original application with this, we see that most of the application is similar. However, we're pretty much stuck here at this point.

Going back to the pcap file, we see some HTTP requests are made to this URL: 

```
http://www.bing.com/search?q=alictf%7BFlagIsHere%7D&go=Submit&qs=n&form=QBRE&
pq=alictf%7Bflagishere%7D&sc=8-7&sp=-1&sk=&setmkt=zh-CN
```
.Looking further, none of the requests seems to be suspicious, except one:
{% highlight bash linenos %}
Frame 1365: 431 bytes on wire (3448 bits), 431 bytes captured (3448 bits)
Ethernet II, Src: RealtekU_12:34:56 (52:54:00:12:34:56), Dst: RealtekU_12:35:02 (52:54:00:12:35:02)
Internet Protocol Version 4, Src: 10.0.2.15, Dst: 202.112.51.218
Transmission Control Protocol, Src Port: 44797 (44797), Dst Port: 80 (80), Seq: 1, Ack: 1, Len: 377
Hypertext Transfer Protocol
    POST /log HTTP/1.1\r\n
        [Expert Info (Chat/Sequence): POST /log HTTP/1.1\r\n]
        Request Method: POST
        Request URI: /log
        Request Version: HTTP/1.1
    User-Agent: Dalvik/1.6.0 (Linux; U; Android 6.0; Android SDK built for x86_64 Build/MASTER)\r\n
    Content-Encoding: gzip\r\n
    Content-Length: 100\r\n
    Content-Type: application/x-www-form-urlencoded\r\n
    Host: log.godric.me\r\n
    Connection: Keep-Alive\r\n
    Accept-Encoding: gzip\r\n
    \r\n
    [Full request URI: http://log.godric.me/log]
    [HTTP request 1/1]
    [Response in frame: 1367]
    Content-encoded entity body (gzip): 100 bytes -> 77 bytes
HTML Form URL Encoded: application/x-www-form-urlencoded
    12106262333962303730363064656162643515b9e8f3d3ca2a181046514bf9f2b3cd3bf580b7cd9bae45141820da2990bf15b7fd98a4e73ef766cd714f6f63b2e7f270c55f0caf7e704ca7702f
{% endhighlight %}

Following this lead, I used a proxy to look for traffic from the APK and indeed, everytime we win the game and enter a highscore, a **POST** request would be made that is similar to the one above. However, the message seems be to encrypted in a certain way by the APK. 

With this, now it's clear that what we have to do is to reverse the logic that is responsible for the encryption and to decrypt the data to get our flag.

We traced the code to this particular function that seems to be invoking the encryption:

{% highlight java linenos %}
  public void a(String paramString)
  {
    byte[] arrayOfByte1 = x.a(d());
    e();
    g();
    byte[] arrayOfByte2 = x.a(f(), h());
    this.d = AES_Encrypt(paramString.getBytes(), arrayOfByte1, arrayOfByte2);
  }
{% endhighlight %}

We found that the encryption is AES in CBC mode (from the constants).

Following that further, we found a class that describes the final representation of the data:

{% highlight java linenos %}
package eu.veldsoft.colors.overflow;

import java.io.OutputStream;

public class f
{
  public static void a(OutputStream paramOutputStream, long paramLong)
  {
    try
    {
      paramOutputStream.write(21);
      while ((0xFFFFFFFFFFFFFF80 & paramLong) != 0L)
      {
        paramOutputStream.write((byte)(int)(0x7F & paramLong | 0x80));
        paramLong >>= 7;
      }
      paramOutputStream.write((byte)(int)paramLong);
      return;
    }
    catch (Exception paramOutputStream)
    {
      paramOutputStream.printStackTrace();
    }
  }
  
  public static void a(OutputStream paramOutputStream, String paramString)
  {
    try
    {
      paramOutputStream.write(18);
      paramOutputStream.write((byte)paramString.length());
      paramOutputStream.write(paramString.getBytes());
      return;
    }
    catch (Exception paramOutputStream)
    {
      paramOutputStream.printStackTrace();
    }
  }
  
  public static void a(OutputStream paramOutputStream, byte[] paramArrayOfByte)
  {
    try
    {
      paramOutputStream.write(24);
      paramOutputStream.write((byte)paramArrayOfByte.length);
      paramOutputStream.write(paramArrayOfByte);
      return;
    }
    catch (Exception paramOutputStream)
    {
      paramOutputStream.printStackTrace();
    }
  }
}
{% endhighlight %}

With this class, we are able to further understand what the data is representing:

```
12 10 62623339623037303630646561626435 => android_id with length 0x10
15 b9e8f3d3ca2a => current_time
18 10 46514bf9f2b3cd3bf580b7cd9bae4514 => encrypted_data with length 0x10
18 20 da2990bf15b7fd98a4e73ef766cd714f6f63b2e7f270c55f0caf7e704ca7702f => encrypted_data2 with length 0x20
```

Compiling and running the decompiled Java code gives us the IV for our AES decryption.

I wrote a simple python script to run the AES decryption with the key and IV.

{% highlight python linenos %}
from Crypto.Cipher import AES
import md5

andid ='bb39b07060deabd5'
cipherText = 'da2990bf15b7fd98a4e73ef766cd714f6f63b2e7f270c55f0caf7e704ca7702f';
def decrypt(cipherText):
    # passphrase MUST be 16, 24 or 32 bytes long, how can I do that ?
    IV = '46514aad58cf3902f580b69931d2b12d'.decode('hex')
    aes = AES.new(md5.new(andid).digest(), AES.MODE_CBC, IV)
    return aes.decrypt(cipherText.decode('hex'))

print decrypt(cipherText,"")
{% endhighlight %}

{% highlight bash linenos %}
$ python color.py
{"alictf{A11IsInTraff1c}":2580}
{% endhighlight %}

And we got our flag! ***alictf{A11IsInTraff1c}***.

