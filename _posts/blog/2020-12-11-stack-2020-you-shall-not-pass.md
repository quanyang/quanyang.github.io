---
layout: post
title: STACK 2020 - You Shall Not Pass
modified:
categories: blog/
excerpt:
tags: []
image:
  feature:
share: true
comments: true
date: 2020-12-11T11:23:16+08:00
---

![]({{site.url|append: site.baseurl}}/resources/images/stack/scoreboard.jpg)

STACK 2020 CTF is a capture the flag [organized by GovTech](https://ctf.tech.gov.sg/). We participated as PwningActionParty and achieved third place in the open category.

# Unlock Me
**Category:** Web  
**Description:** 
We discovered a web portal used by COViD as a C2 platform to send messages to his ransomware victims. They have a script that accesses and hacks the websites posted back to the server! Can you stop them?

---

![]({{site.url|append: site.baseurl}}/resources/images/stack/you-shall-not-pass.png){: width="400px"}

The webpage appears to be a simple Command&Control (C2) platform with two feature:

  1. Add a new website to your list of hacked websites.
  2. Broadcast messages to your victims.

### The first step is to try to observe the behavior each feature exhibits

***1. Add a new website to your list of hacked websites***

From monitoring the network requests, we see that a POST request is made to `http://yhi8bpzolrog3yw17fe0wlwrnwllnhic.alttablabs.sg:41011/link` with the provided URL in the POST body.

{% highlight linenos %}
GET / HTTP/1.1
Host: as6pzzwc9gyz8zkbzw5zhg00rrxil7.burpcollaborator.net
Connection: keep-alive
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/81.0.4044.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Accept-Encoding: gzip, deflate
Accept-Language: en-US
{% endhighlight %}

Using Burp Collaborator, we can easily see that a HTTP request was made to the URL provided through a headless chrome instance.

However, since the response from the request is not returned to the user, we can't escalate this blind SSRF any further.

***2. Broadcast messages to your victim***

From the network requests, we see that a POST request is made to `http://yhi8bpzolrog3yw17fe0wlwrnwllnhic.alttablabs.sg:41011/broadcast`, however, this doesn't seem to result in any network call(s) made to the victim URL from feature 1.



