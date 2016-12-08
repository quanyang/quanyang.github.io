---
layout: post
title: Part 1 - Continuous Pwning of the Top 1000 WordPress Plugins
modified:
categories: blog
excerpt: ""
tags: []
image:
  feature:
share: true
comments: true
date: 2016-12-08T18:56:24+08:00
---

This article is the first part of many on a Taint Analysis Tool I wrote for the PHP Programming Language. This part talks about how I make use of the tool to automatically look for vulnerabilities in the top 1000 WordPress Plugin!

#### Introduction

Most of us are familar with the term Continuous integration (CI) where changes to a code repository could be automatically merged or even deployed. However, security is rarely taken into consideration when setting up CI environments. Even with automated testing in place, vulnerabilities could go undiscovered if testing was not done rigorously.

Taint analysis is a form of information-flow analysis where one can trace tainted inputs from the point of introduction to the point it was used. When a tainted input is used by a sensitive function, it could possibly be a security vulnerability.

The following is one such example; when a tainted input is echo'ed in PHP without going through any sanitization, it introduces a cross-site scripting (XSS) vulnerability.

{% highlight php linenos %}
<?php
    $tainted_input = $_GET['search'];
    echo "You searched for '$tainted_input'";
?>
{% endhighlight %}

As part of my dissertation project, I designed and implemented a Static Taint Analysis tool for the PHP language. In order to improve the precision of the analysis, I augmented the initial Static Taint Analysis with Symbolic Execution and therefore is able to determine if a certain execution path is reachable. You can try out a demo of the tool [here](http://taint.spro.ink).

Now imagine if we integrate this tool into a CI workflow where applications are automatically scanned for taint-based vulnerabilities and vulnerabilities are flagged when found, less vulnerabilities would be introduced into production and less work would be needed for engineers to fix them later.

The rest of this article talks about an experiment I did with the top 1000 WordPress plugins and an example of a vulnerability I found and reported. Though the experiment is not fully automatic, it shows a potential for a fully-automatic process where new plugins could be automatically downloaded and tested.

WordPress plugins makes for a very good testing target as the source-code of plugins are readily available for download and the WordPress sanitizers/sinks are known beforehand.

#### Automatically Download the top 1000 WordPress plugins

A quick search brings up many ways to automatically download WordPress plugins. One such example is [https://github.com/gehaxelt/Python-Wordpress-Plugin-Downloader](https://github.com/gehaxelt/Python-Wordpress-Plugin-Downloader), this script could be used to download the most popular WordPress plugins (Top 1000).

You could also write a simple script to automatically download WordPress plugins of any version from [http://plugins.svn.wordpress.org/](http://plugins.svn.wordpress.org/).

{% highlight bash linenos %}
→ ls -la
...
drwxr-xr-x   999 quanyang  staff  33966 Nov  9 19:34 downloaded
{% endhighlight %}

It takes awhile, but the top 1000 plugins would eventually be downloaded.

#### Continuous Pwning

In the Taint Analysis implementation, it takes in a Taint Policy consisting of Sources, Sinks and Sanitizers. In this case, we can add the known WordPress sanitizers like `esc_attr` and `esc_html` as well as sinks like `query`.

With that, we can then begin to run the tool against all the PHP files in the plugins downloaded. As the tool is written in Python, we can easily write a Python script to enumerate all PHP files and to run the tool against one-by-one. 

In order to speed things up, I also make use of multiprocessing in Python to test 4 different plugins at any instant.

Based on initial testing without true verification of exploitability, it detected a total of **712** possible vulnerability within the top 1000 plugins! However, some of them could be false positives and needs further testing to verify. 

{% highlight bash linenos %}
root@ubuntu-512mb-sgp1-01:/wp_research# python consolidate.py
>
{u'Reflection Injection': 3, u'Code Execution': 11, u'Protocol Injection': 4, u'HTTP Response Splitting': 39, u'Command Execution': 1, u'Session Fixation': 2, u'PHP Object Injection': 30, u'Possible Flow Control': 23, u'SQL Injection': 19, u'File Inclusion': 24, u'File Manipulation': 65, u'File Disclosure': 62, u'Cross-Site Scripting': 429}
Total: 712
{% endhighlight %}

#### Case Study: SSRF in Nelio AB Testing WordPress Plugin

Nelio AB Testing is a WordPress plugin used for A/B Testing in WordPress pages. We can download the source-code of the Plugin from [plugins.svn.wordpress.org/nelio-ab-testing/tags/4.5.8/](plugins.svn.wordpress.org/nelio-ab-testing/tags/4.5.8/).

Server-side Request Forgery (SSRF) is a vulnerability where requests can be made from the vulnerable server to the intra/internet. Though it does not seem to have serious impact, using a protocol supported by certain URI schemes, an attacker could collect various information about the server or even achieve remote code execution (RCE). There is a very comprehensive cheat-sheet for SSRF available [here](https://docs.google.com/document/d/1v1TkWZtrhzRLy0bYXBcdLUedXGb9njTNIJXa3u9akHM/edit).

Zooming in to the vulnerable PHP script at `./ajax/iesupport.php`. It is obvious from manual analysis that we are able to control the URL that would eventually be cURL'ed by the server.

{% highlight php linenos %}
<?php
** Truncated **
$url = false;
$data = false;

if ( isset( $_POST['originalRequestUrl'] ) ) {
    $url = $_POST['originalRequestUrl'];
    $url = preg_replace( '/^\/\//', '', $url );
}
else {
    // Silence is gold
    return;
}

if ( isset( $_POST['data'] ) ) {
    $data = $_POST['data'];
}
else {
    // Silence is gold
    return;
}

$was_data_sent = false;

if ( !$was_data_sent && function_exists( 'curl_version' ) ) {
    //open connection
    $ch = curl_init();

    if ( $ch ) {
        //set the url, number of POST vars, POST data
        curl_setopt( $ch, CURLOPT_URL, $url );
        curl_setopt( $ch, CURLOPT_POST, substr_count( $data, '=' ) );
        curl_setopt( $ch, CURLOPT_POSTFIELDS, $data );
        if ( isset( $_SERVER['HTTP_REFERER'] ) )
            curl_setopt( $ch, CURLOPT_REFERER, $_SERVER['HTTP_REFERER'] );
        if ( isset( $_SERVER['HTTP_USER_AGENT'] ) )
            curl_setopt( $ch, CURLOPT_USERAGENT, $_SERVER['HTTP_USER_AGENT'] );

        //execute post
        $result = curl_exec( $ch );

        //close connection
        curl_close( $ch );

        $was_data_sent = true;
    }
}

** Truncated **
?>
{% endhighlight %}

In fact, the vulnerabilty was found by the tool automatically. We can see an intuitive result from testing the vulnerable script on [http://taint.spro.ink](http://taint.spro.ink). We see that the tool is able to detect the tainted user-input being used in the `curl_setopt` function. 

![](/resources/images/continuouspwning/detection.png)

From [https://pluginu.com/nelio-ab-testing/](https://pluginu.com/nelio-ab-testing/), we can easily see that there are at least 173 websites using this plugin currently! Being lucky, I was able to find a bug bounty program that has a WordPress site using this particular plugin and was able to obtain a bounty with this finding. :)

![](/resources/images/continuouspwning/bug.png)

![](/resources/images/continuouspwning/bounty.png)

**I've since reported this to the plugin author and was told it has been fixed!**

#### Conclusion

What this experiment proved was that it was highly possible for a development cycle/process where applications are continuously tested for vulnerability. However, more work needs to be done to ensure true positives in result and/or to even automatically patch simple vulnerabilities!

This is the first part of many and in the subsequent parts I will write more about the tool in detail!

Thanks for reading!

