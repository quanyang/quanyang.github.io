---
layout: post
title: ALICTF 2016 - LoopAndLoop (Reversing 100)
modified:
categories: blog
excerpt: ""
tags: []
image:
feature:
share: true
comments: true
date: 2016-06-07T01:44:13+02:00
---

# ALICTF 2016 - LoopAndLoop
>**Points:** 100
**Category:** Reversing  
**Description**  
The friendship between native and dex. ([attachment](/resources/files/alictf/LoopAndLoop-android100_b53506eba384796c651d91913aa76d6e.apk))

---

Another android reversing challenge. This was the first challenge I solved in the ALICTF, this one was pretty straightforward. An APK is provided, and as usual I first decompile it with apktool and dex2jar.

![](/resources/images/alictf/loopandloop.png)

Upon decompilation with apktool, you'll notice a `/lib` directory which clearly signifies that this apk uses some kind of shared library, and commonly in CTF challenges with APKs, you'd usually be required to reverse the logic found in the shared library.

Next, looking at the dex2jar output, we see some kind of recursive check function that makes use of a function defined in the shared library. 

The logic is mainly in the following few snippets of codes:
{% highlight java linenos %}
public void main() {
    if (this.check(i, 99) == 1835996258) {
        localTextView1.setText("The flag is:");
        localTextView2.setText("alictf{" + MainActivity.this.stringFromJNI2(i) + "}");
        return;
    }
}

public native int chec(int paramInt1, int paramInt2);

public int check(int paramInt1, int paramInt2) {
    return chec(paramInt1, paramInt2);
}

public int check1(int paramInt1, int paramInt2) {
    int j = 1;
    int i = paramInt1;
    paramInt1 = j;
    while (paramInt1 < 100) {
      i += paramInt1;
      paramInt1 += 1;
    }
    return chec(i, paramInt2);
}

public int check2(int paramInt1, int paramInt2) {
    if (paramInt2 % 2 == 0) {
      j = 1;
      i = paramInt1;
      paramInt1 = j;
      while (paramInt1 < 1000) {
        i += paramInt1;
        paramInt1 += 1;
      }
      return chec(i, paramInt2);
    }
    int j = 1;
    int i = paramInt1;
    paramInt1 = j;
    while (paramInt1 < 1000) {
      i -= paramInt1;
      paramInt1 += 1;
    }
    return chec(i, paramInt2);
}

public int check3(int paramInt1, int paramInt2) {
    int j = 1;
    int i = paramInt1;
    paramInt1 = j;
    while (paramInt1 < 10000) {
      i += paramInt1;
      paramInt1 += 1;
    }
    return chec(i, paramInt2);
}
{% endhighlight %}

And the shared library function reversed to give:
{% highlight c linenos %}
int __fastcall Java_net_bluelotus_tomorrow_easyandroid_MainActivity_chec(int a1, int a2, int a3, int a4)
{
  int v4; // r4@1
  int v5; // r7@1
  int result; // r0@2
  int v7; // [sp+Ch] [bp-34h]@1
  int v8; // [sp+10h] [bp-30h]@1
  int v9; // [sp+14h] [bp-2Ch]@1
  int v10; // [sp+1Ch] [bp-24h]@1
  int v11; // [sp+20h] [bp-20h]@1
  int v12; // [sp+24h] [bp-1Ch]@1

  v9 = a2;
  v8 = a4;
  v4 = a1;
  v7 = a3;
  v5 = (*(int (**)(void))(*(_DWORD *)a1 + 24))();
  v10 = _JNIEnv::GetMethodID(v4, v5, "check1", "(II)I");
  v11 = _JNIEnv::GetMethodID(v4, v5, "check2", "(II)I");
  v12 = _JNIEnv::GetMethodID(v4, v5, "check3", "(II)I");
  if ( v8 - 1 <= 0 )
    result = v7;
  else
    result = _JNIEnv::CallIntMethod(v4, v9, *(&v10 + 2 * v8 % 3));
  return result;
}
{% endhighlight %}

Rewriting the entire logic in Python and we have our solution!
{% highlight python linenos %}
target = 1835996258

def check(one, two):
    if two <= 1:
        return one
    if (2*two) % 3 == 0:
        return check1(one,two-1)
    elif (2*two) %3 == 1:
        return check2(one,two-1)
    else:
        return check3(one,two-1)

def check1(paramInt1,paramInt2):
    j = 1;
    i = paramInt1;
    paramInt1 = j;
    while paramInt1 < 100:
      i += paramInt1;
      paramInt1 += 1;
    return check(i, paramInt2)

def check2(paramInt1,paramInt2):
    if paramInt2 % 2 == 0:
      j = 1;
      i = paramInt1;
      paramInt1 = j;
      while paramInt1 < 1000:
        i += paramInt1;
        paramInt1 += 1;
      return check(i, paramInt2);
    j = 1;
    i = paramInt1;
    paramInt1 = j;
    while paramInt1 < 1000:
      i -= paramInt1;
      paramInt1 += 1;
    return check(i, paramInt2);

def check3(paramInt1,paramInt2):
    j = 1;
    i = paramInt1;
    paramInt1 = j;
    while (paramInt1 < 10000):
      i += paramInt1;
      paramInt1 += 1;
    return check(i, paramInt2);

print check(236492408,99) == target
{% endhighlight %}

![](/resources/images/alictf/loopflag.png)

Entering `236492408` into the application gives us our flag! ***alictf{Jan6N100p3r}***.