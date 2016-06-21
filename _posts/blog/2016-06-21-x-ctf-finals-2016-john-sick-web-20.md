---
layout: post
title: X-CTF Finals 2016 - John Sick (Web 20)
modified:
categories: blog
excerpt: ""
tags: []
image:
feature:
share: true
comments: true
date: 2016-06-21T21:51:55+02:00
---

X-CTF is a capture the flag competition in Singapore organized by NUS Greyhats. The on-site finals took place on Saturday, 18 June 2016. This is another one of the web challenge I wrote for the finals. All of the web challenges I wrote are done with the same front-end UI to make things simpler.

# JohnSick
>**Points:** 20  
**Category:** Web  
**Description:**  Flag is on the server. Get the source code of index.php to find the flag. [http://bg3.spro.ink:8080](http://bg3.spro.ink:8080)

---

For this challenge, the truncation issue in the registration feature of web 15 has been fixed. So, the first step is to register and login as any user.

The description of the challenge tells you to obtain the source code of index.php, this also hints that there must be a way to obtain the source code.

![](/resources/images/x-ctf/johnsick_upload.png)

After logging in, we see that there's a feature for users to upload images. However, it says clearly that only jpg is allowed. 

![](/resources/images/x-ctf/johnsick_uploaded.png){: width="600px"}

If you tried uploading using a URL of a valid JPG image, you'd see that the image would be successfully uploaded and displayed. However, if you tried any links that does not end with `.jpg`, you'd see that the upload would fail and no image would be shown. This was actually due to a filter on the URL.

{% highlight PHP linenos %}
<?php
if (!filter_var($url, FILTER_VALIDATE_URL) === false && preg_match("/^https?:\/\/.*\.jpg$/", $url)) {
    $url = getRedirectUrl($url);
    $contents = file_get_contents($url);
    $name = md5($_POST['username']);
    $url = "./hitimages/" . $name . "_" . $_POST['username'] . ".jpg";
    $imageFile = fopen($url,"wb");
    if ($imageFile) {
        fwrite($imageFile, $contents);
        $file = $url;
        fclose($imageFile);
    }
}
?>
{% endhighlight %}

So, the trick here is to make use of a 301 redirect in order to redirect the request to a URL that does not start with `http(s)` and ends with `.jpg`. We can use a simple PHP server and modify the configuration for it to execute `.jpg` files as PHP and with a short PHP script, perform the redirect.
 
{% highlight php linenos %}
<?php
header('HTTP/1.1 301 Redirect');
header('Location: php://filter/string.toupper/resource=index.php');
?>
{% endhighlight %}

This way, it'd allow us to obtain the source code of `index.php`. If you tried this, you'd see that the image would not be rendered as the image is corrupted and if you view the source of the image, you'd get the source code of `index.php`

![](/resources/images/x-ctf/johnsick_source.png)

And with that, you can easily read the flag from the `flag_is_here.lol` file. This is an example of a server-side request forgery (SSRF) vulnerability, SSRF is recently becoming more common (imagemagick is on fire vulnerability). 

Another interesting fact is, if you tried all the different schemes that PHP supports, you'd see that only PHP, HTTP and HTTPS is supported and this is because all the other schemes has been disabled. You might not already know this, but many of these URI schemes are actually enabled by default. 

{% highlight php linenos %}
<?php
$scheme = ["ftp", "zlib", "data", "glob", "phar", "ssh2", "rar", "ogg","ftps","compress.zlib","compress.bzip2","zip"];
foreach ($scheme as $i) {
  stream_wrapper_unregister($i);
}
?>
{% endhighlight %}

And so, with this we got our flag: `XCTF{J0HN_G0T_R3D1R3CT3D}`.