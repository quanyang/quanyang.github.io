---
layout: post
title: X-CTF Finals 2016 - John Wick (Web 15)
modified:
categories: blog
excerpt: ""
tags: []
image:
  feature:
share: true
comments: true
date: 2016-06-20T22:48:40+02:00
---

X-CTF is a capture the flag competition in Singapore organized by NUS Greyhats. The on-site finals took place on Saturday, 18 June 2016. This is one of the web challenge I wrote for the finals.

# JohnWick
>**Points:** 20  
**Category:** Web  
**Description:** Login as 'johnwick' and find the flag. [http://bg2.spro.ink:8080](http://bg2.spro.ink:8080)

---

This challenge was meant to be easy and as a warm up for the participants.

![](/resources/images/x-ctf/johnwick_login.png)

In the description it is given that we're suppose to login as the user 'johnwick', this is actually the first part of the challenge.

As you can see, there seems to be a character limit of 30 characters for the username. However, if you tried to enter more than 30 characters, you'd see that the registration still succeeds and if you tried logging in with the truncated username to 30 characters, you'll see that you are able to login successfully.

![](/resources/images/x-ctf/30characters.png){:width="400px"}
![](/resources/images/x-ctf/30characters_login.png)

The truncation is actually caused by the database during insertion. As the username field has a varchar length of 30 characters, during insertion any value would automatically be truncated to 30 characters.

{% highlight mysql linenos %}
CREATE TABLE users (
    id INT NOT NULL AUTO_INCREMENT,
    username varchar(30) NOT NULL,
    password varchar(64) NOT NULL,
    address varchar(256),
    isAdmin INT DEFAULT 0,
    PRIMARY KEY (id)
);
{% endhighlight %}

This bug is actually due to few issues:

1. There's no user input validation that ensures user input to be 30 characters or less.
2. The 'username' column should have been unique or a primary key.

Exploiting this vulnerability, we can now create another 'johnwick' user with our chosen password.

![](/resources/images/x-ctf/johnwick_search.png)

After logging in, you will be able to access the search feature, which is the second part of this challenge.

The second part of the challenge is meant to be an SQL injection vulnerability. If you tried `' or '1'='1` and `' and '1'='2` you can immediately tell that there's an injection vulnerability. Initially there was a space filter in place to make the challenge harder, but after some time and no solves, the filter was removed.

{% highlight php linenos %}
$sql = "SELECT username FROM users WHERE username like '%".str_replace(" ", "", $username)."%';";
{% endhighlight %}

One way to tell that it was a space filter was to try something like this: `'and(username='johnwick');` versus `' and username='johnwick';`, should there be a space filter, the second query should not work.

To bypass the space filter, you could simply use tabs (%09) or newlines (%0a) instead of spaces. Another way is to use parenthesis, like the following payload: `'union(select(address)from(users));`

Doing so will get you the flag: `XCTF{S0_W!CK3D_TRUNC@T3D}`. I thought that this would have been an easy challenge, but most of the participants did not manage to get pass the space filter.