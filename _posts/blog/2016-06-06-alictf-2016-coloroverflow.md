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
date: 2016-06-11T21:24:20+02:00
---

# ALICTF 2016 - ColorOverflow
>**Points:** 100
**Category:** Reversing  
**Description**  
ctf=Capture The traFfic? ([attachment](/resources/files/alictf/ColorOverflow_6c305d0795155a3fefbd47a4515fe06b.pcap))  
HINT: port 5555

---

I only looked at this challenge after some time and by the time I started looking at it, quite a few teams have solved it already and the organizers has given out additional hint to look at **port 5555**.

The packet capture provided has quite a bit of HTTP traffic as well as traffic on port 5555. If you are familiar with Android debugging, port 5555 is often use for adb traffic. Looking at the conversation it is obvious that an apk is uploaded and installed onto the device.

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

The APK application appears to be a real game available on the [playstore](https://play.google.com/store/apps/details?id=eu.veldsoft.colors.overflow&hl=en).
After decompiling the APK with apktool, we see that within the assets folder, there is a HTML file with a GitHub link to the [original game](http://github.com/TodorBalabanov/ColorsOverflow).

Comparing the original application with this, we see that most of the application is similar. Going back to the pcap file, we see that some HTTP requests are made to this URL: 

```
http://www.bing.com/search?q=alictf%7BFlagIsHere%7D&go=Submit&qs=n&form=QBRE&
pq=alictf%7Bflagishere%7D&sc=8-7&sp=-1&sk=&setmkt=zh-CN
```
Looking further, none of the requests seems to be suspicious, except one:
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

![](/resources/images/alictf/colorhighscore.png)

With this, now it's clear that what we have to do is to reverse the logic that is responsible for the encryption and to decrypt the data to get our flag. We first search for the URL in the request and trace the code. It starts here:

{% highlight java linenos %}
package eu.veldsoft.colors.overflow;
**Truncated**
public class o extends AsyncTask {
  private static byte[] a(byte[] paramArrayOfByte)
  {
    ByteArrayOutputStream localByteArrayOutputStream = new ByteArrayOutputStream();
    GZIPOutputStream localGZIPOutputStream = new GZIPOutputStream(localByteArrayOutputStream);
    localGZIPOutputStream.write(paramArrayOfByte);
    localGZIPOutputStream.close();
    localByteArrayOutputStream.close();
    return localByteArrayOutputStream.toByteArray();
  }
  **Truncated**
  protected String a(ByteArrayOutputStream[] paramArrayOfByteArrayOutputStream) {
    return a(b("http://log.godric.me/log"), paramArrayOfByteArrayOutputStream[0].toByteArray());
  }
}
{% endhighlight %}

We traced the code to this particular function that seems to be invoking the encryption:

{% highlight java linenos %}
  public void a(String paramString)
  {
    byte[] arrayOfByte1 = x.a(d());
    e();
    g();
    byte[] arrayOfByte2 = x.a(f(), h());
    this.d = AES.Encrypt(paramString.getBytes(), arrayOfByte1, arrayOfByte2);
  }
{% endhighlight %}

We found that the encryption performed is AES in CBC mode. You can easily tell from the constants, and can verify by checking the values.

{% highlight java linenos %}
package eu.veldsoft.colors.overflow;
**Truncated**
public class AES {
  **Truncated**
  private static int[] e = { 99, 124, 119, 123, 242, 107, 111, 197, 48, 1, 103, 43, 254, 215, 171, 118, 202, 130, 201, 125, 250, 89, 71, 240, 173, 212, 162, 175, 156, 164, 114, 192, 183, 253, 147, 38, 54, 63, 247, 204, 52, 165, 229, 241, 113, 216, 49, 21, 4, 199, 35, 195, 24, 150, 5, 154, 7, 18, 128, 226, 235, 39, 178, 117, 9, 131, 44, 26, 27, 110, 90, 160, 82, 59, 214, 179, 41, 227, 47, 132, 83, 209, 0, 237, 32, 252, 177, 91, 106, 203, 190, 57, 74, 76, 88, 207, 208, 239, 170, 251, 67, 77, 51, 133, 69, 249, 2, 127, 80, 60, 159, 168, 81, 163, 64, 143, 146, 157, 56, 245, 188, 182, 218, 33, 16, 255, 243, 210, 205, 12, 19, 236, 95, 151, 68, 23, 196, 167, 126, 61, 100, 93, 25, 115, 96, 129, 79, 220, 34, 42, 144, 136, 70, 238, 184, 20, 222, 94, 11, 219, 224, 50, 58, 10, 73, 6, 36, 92, 194, 211, 172, 98, 145, 149, 228, 121, 231, 200, 55, 109, 141, 213, 78, 169, 108, 86, 244, 234, 101, 122, 174, 8, 186, 120, 37, 46, 28, 166, 180, 198, 232, 221, 116, 31, 75, 189, 139, 138, 112, 62, 181, 102, 72, 3, 246, 14, 97, 53, 87, 185, 134, 193, 29, 158, 225, 248, 152, 17, 105, 217, 142, 148, 155, 30, 135, 233, 206, 85, 40, 223, 140, 161, 137, 13, 191, 230, 66, 104, 65, 153, 45, 15, 176, 84, 187, 22 };
  private static int[] f = { 82, 9, 106, 213, 48, 54, 165, 56, 191, 64, 163, 158, 129, 243, 215, 251, 124, 227, 57, 130, 155, 47, 255, 135, 52, 142, 67, 68, 196, 222, 233, 203, 84, 123, 148, 50, 166, 194, 35, 61, 238, 76, 149, 11, 66, 250, 195, 78, 8, 46, 161, 102, 40, 217, 36, 178, 118, 91, 162, 73, 109, 139, 209, 37, 114, 248, 246, 100, 134, 104, 152, 22, 212, 164, 92, 204, 93, 101, 182, 146, 108, 112, 72, 80, 253, 237, 185, 218, 94, 21, 70, 87, 167, 141, 157, 132, 144, 216, 171, 0, 140, 188, 211, 10, 247, 228, 88, 5, 184, 179, 69, 6, 208, 44, 30, 143, 202, 63, 15, 2, 193, 175, 189, 3, 1, 19, 138, 107, 58, 145, 17, 65, 79, 103, 220, 234, 151, 242, 207, 206, 240, 180, 230, 115, 150, 172, 116, 34, 231, 173, 53, 133, 226, 249, 55, 232, 28, 117, 223, 110, 71, 241, 26, 113, 29, 41, 197, 137, 111, 183, 98, 14, 170, 24, 190, 27, 252, 86, 62, 75, 198, 210, 121, 32, 154, 219, 192, 254, 120, 205, 90, 244, 31, 221, 168, 51, 136, 7, 199, 49, 177, 18, 16, 89, 39, 128, 236, 95, 96, 81, 127, 169, 25, 181, 74, 13, 45, 229, 122, 159, 147, 201, 156, 239, 160, 224, 59, 77, 174, 42, 245, 176, 200, 235, 187, 60, 131, 83, 153, 97, 23, 43, 4, 126, 186, 119, 214, 38, 225, 105, 20, 99, 85, 33, 12, 125 };
  private static int[] g = { 141, 1, 2, 4, 8, 16, 32, 64, 128, 27, 54, 108, 216, 171, 77, 154, 47, 94, 188, 99, 198, 151, 53, 106, 212, 179, 125, 250, 239, 197, 145, 57, 114, 228, 211, 189, 97, 194, 159, 37, 74, 148, 51, 102, 204, 131, 29, 58, 116, 232, 203, 141, 1, 2, 4, 8, 16, 32, 64, 128, 27, 54, 108, 216, 171, 77, 154, 47, 94, 188, 99, 198, 151, 53, 106, 212, 179, 125, 250, 239, 197, 145, 57, 114, 228, 211, 189, 97, 194, 159, 37, 74, 148, 51, 102, 204, 131, 29, 58, 116, 232, 203, 141, 1, 2, 4, 8, 16, 32, 64, 128, 27, 54, 108, 216, 171, 77, 154, 47, 94, 188, 99, 198, 151, 53, 106, 212, 179, 125, 250, 239, 197, 145, 57, 114, 228, 211, 189, 97, 194, 159, 37, 74, 148, 51, 102, 204, 131, 29, 58, 116, 232, 203, 141, 1, 2, 4, 8, 16, 32, 64, 128, 27, 54, 108, 216, 171, 77, 154, 47, 94, 188, 99, 198, 151, 53, 106, 212, 179, 125, 250, 239, 197, 145, 57, 114, 228, 211, 189, 97, 194, 159, 37, 74, 148, 51, 102, 204, 131, 29, 58, 116, 232, 203, 141, 1, 2, 4, 8, 16, 32, 64, 128, 27, 54, 108, 216, 171, 77, 154, 47, 94, 188, 99, 198, 151, 53, 106, 212, 179, 125, 250, 239, 197, 145, 57, 114, 228, 211, 189, 97, 194, 159, 37, 74, 148, 51, 102, 204, 131, 29, 58, 116, 232, 203 };
  **Truncated**
}
{% endhighlight %}

Following that further, we found a class that describes the final representation of the data:

{% highlight java linenos %}
package eu.veldsoft.colors.overflow;
**Truncated**
public class customDataStructure {
  public static void timeOfEncryption(OutputStream paramOutputStream, long paramLong) {
    try {
      paramOutputStream.write(21);
      while ((0xFFFFFFFFFFFFFF80 & paramLong) != 0 L) {
        paramOutputStream.write((byte)(int)(0x7F & paramLong | 0x80));
        paramLong >>= 7;
      }
      paramOutputStream.write((byte)(int) paramLong);
      return;
    } catch (Exception paramOutputStream) {
      paramOutputStream.printStackTrace();
    }
  }

  public static void android_id(OutputStream paramOutputStream, String paramString) {
    try {
      paramOutputStream.write(18);
      paramOutputStream.write((byte) paramString.length());
      paramOutputStream.write(paramString.getBytes());
      return;
    } catch (Exception paramOutputStream) {
      paramOutputStream.printStackTrace();
    }
  }

  public static void data(OutputStream paramOutputStream, byte[] paramArrayOfByte) {
    try {
      paramOutputStream.write(24);
      paramOutputStream.write((byte) paramArrayOfByte.length);
      paramOutputStream.write(paramArrayOfByte);
      return;
    } catch (Exception paramOutputStream) {
      paramOutputStream.printStackTrace();
    }
  }
}
{% endhighlight %}

And that class was used here:

{% highlight java linenos %}
package eu.veldsoft.colors.overflow;
**Truncated**
public class n {
  **Truncated**
  public ByteArrayOutputStream i() {
    try {
      this.byteOutputStream.reset();
      customDataStructure.android_id(this.byteOutputStream, this.android_id);
      customDataStructure.timeOfEncryption(this.byteOutputStream, System.currentTimeMillis());
      customDataStructure.data(this.byteOutputStream, this.SHA1PRNG);
      customDataStructure.data(this.byteOutputStream, this.highScoreDataPlusMessage);
      this.byteOutputStream.flush();
      return this.byteOutputStream;
    } catch (Exception localException) {
      for (;;) {
          localException.printStackTrace();
      }
    }
  }
}
{% endhighlight %}

With this class, we are able to further understand what the data is representing:

```
12 10 62623339623037303630646561626435 => android_id with length 0x10
15 b9e8f3d3ca2a => current_time
18 10 46514bf9f2b3cd3bf580b7cd9bae4514 => SHA1PRNG with length 0x10
18 20 da2990bf15b7fd98a4e73ef766cd714f6f63b2e7f270c55f0caf7e704ca7702f => highScoreDataPlusMessage with length 0x20
```

Compiling and running the decompiled Java code gives us the IV required for the AES decryption.

Using a simple python script to run the AES decryption with the key and IV.

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

