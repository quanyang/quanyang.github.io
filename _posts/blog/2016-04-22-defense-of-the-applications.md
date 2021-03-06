---
layout: post
title: Defense of the Applications.
modified:
categories: blog
excerpt: "What to look out for when building a web application."
tags: []
image:
  feature:
share: true
comments: true
date: 2016-04-22T16:41:52+08:00
---

At NUS School of Computing, a project showcase is held nearing to the end of every semester. For this semester, I had no projects in the showcase, I was instead participating under a very different role. Closer to STePS, Dr. Steven Halim invited me to help perform security audit on a dozen websites developed by his students in a module which would be showcased during STePS.

I started manually auditing each and every web application, identifying vulnerabilities from simple ones like XSS to SQLi. I was shocked by some of the coding practices as well as deployment techniques as many of the vulnerabilities found were simple to fix and should have never been there. Therefore I decided to write this post to share the more commonly found vulnerabilties as well as severe ones that should never have existed with good deployment practices. 

**DISCLAIMER: I am writing this not to shame any of the teams or individuals, but to share information that would be helpful to other people in the same situation.**

# Cross-Site Scripting

Out of the 12 websites, three of them had XSS vulnerabilities. All of the three application were vulnerable to XSS due to unsanitized input/output. Had they used some kind of front-end framework like AngularJS, the issue would have been half solved by the framework, and from the way the application is behaving, I am highly suspecting that they are not using any kind of back-end framework (e.g Laravel for PHP), which would have some kind of escaping feature in place.

![](/resources/images/dota/XSS1.png)
This application allows you to create posts, and image elements was allowed in the content along with many other HTML elements. The application also allows for markdown formatting, which provided for another vector for XSS using `[XSS](http://quanyang.github.io "onmouseover=alert(1);//,)` as a payload. 

The mistake made by them here is to leave the output unsanitized and to provide for markdown formatting without fully understanding the potential for vulnerabilities.

![](/resources/images/dota/XSS2.png)
The second application, similar to the one before, allows you to create posts, and likewise inputs and outputs were not sanitized. After they 'patched' the initial XSS vulnerability, I went back to take a second look and realized that all they did was to escape the input using JavaScript before sending the data over to the backend endpoint, which was useless as I could still do a HTTP POST directly with the same payload. 

![](/resources/images/dota/XSS2.5.png)

This same application had many other vulnerabilities (you will see later), and the majority of them wouldn't have existed had they used a proper back-end framework instead of writing from ground-up (observed through the application's behaviour). At this point in time, there is still an XSS vulnerability on one of the input form. However, this field is not shown to any other user other than yourself, this is also called **self-XSS**, which may or may not be dangerous depending on situation. 

![](/resources/images/dota/XSS3.png)

For the third application, the XSS vulnerability was kind of different as I managed to inject the payload in using an unauthenticated endpoint that I found through auditing the JavaScript source code. The endpoint allows me to add new schedules to the calendar and as the outputs were not sanitized, they became sinks for XSS. Likewise, the vulnerability wouldn't have exist if they had used a framework instead.

## Take-away from XSS
1. Use frameworks if possible, unless you're very familiar with the language and system. However, even with a framework, you still have to understand and utilize the framework properly in order to prevent simple vulnerabilities and to not introduce more.
2. Don't implement markdown formatting without prior experience/knowledge.
3. Sanitize **ALL** input/output regardless, and if needed, use the white list instead of black list approach. 
4. Never assume that an output would only come from an authorized user. Hidden endpoints could be discovered, and if not secured, would result in vulnerabilities.

# SQL Injection

SQL injection wasn't as easy to find as XSS, but was still present in some of the applications. Out of the 12, three of the sites was/is vulnerable to SQLi. I'd say SQLi could be more severe than XSS as it allows an attacker to dump your entire database, and if suitable, even be able to spawn a shell and perform further exploitation from within the servers. 

![](/resources/images/dota/SQL1.jpeg)

From the image, you can obviously see the SQL errors as well as that the output includes the row which was union'ed together by the injected SQL query. Also, the SQL errors helps provide information on what type of OS (Some kind of Linux) as well as the filepath of the web service. For this case, I did not attempt to enumerate further and stopped here as it provided sufficient evidence that the vulnerability exists.

![](/resources/images/dota/SQL2.png){: width="350px"}![](/resources/images/dota/SQL2.5.png){: width="350px"}

This is the same application that was vulnerable to XSS earlier and this time, it is also vulnerable to SQLi with many of the endpoints vulnerable. It is noticeable that the difference between the two reponse is in the number of quotes, which strongly indicates an SQL error that happens when an opening quote is not closed. However, exploitation for this particular application is a little bit more tricky due to the way queries were written. Likewise, SQL injection would not have been possible with the use of a framework or prepared statements. 

![](/resources/images/dota/SQL3.png)
![](/resources/images/dota/SQL3.5.png)

For the third application, initially this same endpoint was vulnerable to directory traversal that allows me to obtain any arbitrary file on the server. However, that has now been patched and I instead found that this other parameter is vulnerable to SQL injection. The way I verify this is interesting. An experienced MySQL developer would know that `;--` (I added the semi-colon to make it more obvious) is used for commenting in SQL. However, `;-- ` only works when there's a space or line-break after. From the two image, you can see that the page loaded fine (though invalid file) when the space (%20) was added. The two images looks like two different pages but the difference is due to a redirection done by the website.

## Take-away from SQL injection
1. Refer to XSS lesson #1. Sometimes using an ORM (e.g. Eloquent on Laravel) would reduce the need to write queries and as a result, less vulnerabilities introduced.
2. Please sanitize **ALL** input before using them in a database query.
3. If not lazy, use prepared statements for all queries. **HIGHLY RECOMMENDED**
4. Never store user password in plaintext, always use hash+salt. For PHP you can use the `hash_password` native function to handle the hashing and salting for you. 
5. Never use the root user for DB connections, always create a separate user and provide only the least amount of privileges. This is also called the principle of least privilege.

# Business Logic Vulnerability

Business logic vulnerability is when there is a lack of or broken security control. In this context, the issue takes place usually on API endpoints where data modification/insertion/selection is done. This was the most common issue amongst the 12 websites; six of them had issues with business logic.

The following is an example using one of the 12 application:
![](/resources/images/dota/bl1.png)
Here, we are looking at a post made by `quanyang` with the post id of 11.
![](/resources/images/dota/bl2.png)
Here, we have a delete request JavaScript function that was found through auditing the JavaScript source code. Also, notice that I am now logged out of user `quanyang`. 
![](/resources/images/dota/bl3.png)
After invoking the deletion function with the post id of 11, we see that the post with id 11 no longer exists. Showing that the deletion works and that the endpoint does not have any access control or authentication in place.

For most of the applications, the possible outcome of an exploitation of a business logic vulnerability would be to have content deleted/modified/viewed by unauthorized users. 

![](/resources/images/dota/bl4.png)

In this application, an attacker is able to obtain information on all the modules ever taken by a student simply by changing the matric number respectively. The web application did not put in place any access control or validation to ensure that the matric number belongs to the user currently logged in.

In another application, due to a business logic vulnerability, I was able to plant an XSS payload onto the website without having to be authenticated as an admin or user (this was mentioned earlier).

## Take-away
1. Never assume that no one would attempt to perform actions outside of what is allowed on the user interface/website.
2. Security through Obscurity violates Kerckhoffs' Principle, never assume that no one would find the API endpoints you did not secure.

# Miscellaneous stuff
Some other miscellaneous issues (not neccessarily vulnerabilities) that provided information which was useful for me to proceed further.

### Directory Enumeration  
![](/resources/images/dota/DE.png){: width="400px"}  
This would be useful for an attacker to learn more about your website. Some information I could gather would be like what files you have, what backend language you are using, what kind of naming convention do you follow (which can be useful for other stuff), what other pages can I view and in this case where's your admin page.

Although it is commonly said not to secure a system through obscurity, what it really means is that you should not rely on obscurity as the only layer of defense. A layered defense is always better when implemented and designed properly. 

To hide the directory listing, one simple way is to create an `index.html` page in every directory. However, this isn't very elegant and might irk some people. To solve it more elegantly, you could modify the webserver configuration.

For Apache, instead of the following:
{% highlight html linenos%}
<Directory /var/www/>
        Options Indexes FollowSymLinks
        AllowOverride None
        Require all granted
</Directory>
{% endhighlight %}
Remove the Indexes option to disable the directory listings.
{% highlight html linenos%}
<Directory /var/www/>
        Options FollowSymLinks
        AllowOverride None
        Require all granted
</Directory>
{% endhighlight %}

Another way is to insert the following into an `.htaccess` file inside the directory you would like to disable listing for:

```
Options -Indexes  
```

### Pages that requires authentication
Here's a pretty rare one, I never thought I'd ever find one of these around. For the following part, I'll be using the PHP language to explain the behavior, as well as to solve it.

For PHP, here's how a typical developer would check if a user is login, else redirect.
{% highlight php linenos %}
<?php
    session_start();
    if (!isset($_SESSION['userid'])) {
        //Check if user is not logged in
        header('location: login.php');
    }

    // Assume logged in and print some data or information
    echo 'FLAG{123}';
?>
{% endhighlight %}

We can see that if we perform a curl to the page, the FLAG is sent to us. This is because curl by default do not follow redirections.
{% highlight bash linenos %}
→ curl https://**redacted**/test.php -i
HTTP/1.1 302 Moved Temporarily
Server: nginx/1.8.1
Date: Sat, 23 Apr 2016 16:42:24 GMT
Content-Type: text/html
Transfer-Encoding: chunked
Connection: keep-alive
X-Powered-By: PHP/5.5.9-1ubuntu4.14
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate, post-check=0, pre-check=0
Pragma: no-cache
location: test.php?notloggedin

FLAG{123}
{% endhighlight %}

And this was exactly what one of the application did, the following snippet shows the reply from the server when I did a curl to the admin page.

{% highlight html linenos %}
→ curl **redacted**/php/admin.php
<!DOCTYPE HTML>
<html>
<head>
**Truncated**
<script>
function getData(sel){
    var value=sel.value;
    console.log(value);
    $.ajax({
     url: "**redacted**",
     method: "POST",
     data: {'type':"**redacted**",'**redacted**':value
     },
     success:function(data){
        var parsed=$.parseJSON(data);
        $("#displayData th").remove();
        $("#displayData tr").remove();
        if(parsed.TableData!=null){
            **Truncated**
        }
        }
     }
    })
}
**Truncated**
</script>
</html>
{% endhighlight %}

What they should have done was to make a function call to `die()` after the redirection or to encapsulate the entire else logic into an else conditional. 

{% highlight php linenos %}
<?php
    session_start();
    if (!isset($_SESSION['userid'])) {
      //Check if user is not logged in
      header('location: login.php');
      die();
    } else {
      //User is logged in
    }
?>
{% endhighlight %}

### Debugging Information/Error Messages

The first thing to do when deploying an application to the production server is to turn off all debugging messages and error messages. Error/debugging messages allows an attacker to learn what kind of framework you're using, and in some case even backdoors you've planted. 

For PHP, you can disable PHP errors by calling the following in a PHP script:
{% highlight php linenos %}
ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);
{% endhighlight %}

# Destroying the Ancients

This portion of the post will be about the steps I took to obtain credentials to the server, database and back-end sourcecodes of one of the application. I'll be focusing on the mistakes made by the developers along the way as I describe the steps.

I was auditing this same application for the second time, and as the application has very little features, the attack surface on the website itself was limited. As such, this was the only application in which I delved into attacking the infrastructure as well.

The first thing to do was to gather more information on the servers. Using Nmap, I could find out what ports are open and what services are running easily.

{% highlight bash linenos %}
→ nmap -A **redacted**

Starting Nmap 6.47 ( http://nmap.org ) at 2016-04-24 01:09 SGT
Nmap scan report for **redacted** (**redacted**)
Host is up (0.014s latency).
Not shown: 996 closed ports
PORT     STATE SERVICE    VERSION
22/tcp   open  ssh        (protocol 2.0)
| ssh-hostkey:
**redacted**
80/tcp   open  http       Apache httpd 2.4.7 ((Ubuntu))
| http-git:
|   **redacted**/.git/
|     Git repository found!
**truncated**
3306/tcp open  mysql      MySQL 5.5.46-0ubuntu0.14.04.2
| mysql-info:
**truncated**
8080/tcp open  tcpwrapped
**truncated**
Nmap done: 1 IP address (1 host up) scanned in 11.81 seconds
{% endhighlight %}

Two very severe mistakes were made by this group.  
**1)** Do not ever ever ever `git clone` directly into your webserver's public directory (We'll see why later).  
**2)** Never ever ever expose your MySQL service to the public, unless you know what you're doing.

So what's next?  
![](/resources/images/dota/git.png){: width="300px"}  
Obviously, download the entire `.git` folder! How to do this? Using `wget`. Those unfamiliar with git might ask, so what can you do with the `.git` folder?  
Here's what you could do:
{% highlight bash linenos %}
→ git clone .git **redacted**
Cloning into '**redacted**'...
done.
→ ls **redacted**
**truncated**
backup database.sql
backup for basic sql structure.sql
**truncated**
db
**truncated**
login.php
loginFB.php
loginFBCallback.php
**truncated**
{% endhighlight %}

Doing so allows you to obtain the entire content of the Git repository.

What's next? Do a search for passwords and token! Obviously, the first place is to look at the `db` folder.
{% highlight php linenos %}
→ cat db/**redacted**.php
<?php // connect.php basically contains these commands

    define("db_host", "**redacted**");
    //define("db_host", "localhost");
    define("db_uid", "**redacted**");
    define("db_pwd", "**redacted**");
    define("db_name", "**redacted**");

$db = new mysqli(db_host, db_uid, db_pwd, db_name);

if ($db->connect_errno) // are we connected properly?
  exit("Failed to connect to MySQL, exiting this script");


?>
{% endhighlight %}

Tada! Now we have the database password. What do we look for next? Secret tokens for Facebook!
{% highlight php linenos %}
→ cat loginFB.php
<?php
    session_start();
    require_once __DIR__ . '/facebook-php-sdk-v4-5.0.0/src/Facebook/autoload.php';

    $fb = new Facebook\Facebook([
      'app_id' => '**redacted**',
      'app_secret' => '**redacted**',
      'default_graph_version' => 'v2.5',
    ]);

    $helper = $fb->getRedirectLoginHelper();
    $permissions = ['email', 'public_profile'];
    //the loginUrl should only be generated and shown when the user is not logged in
    $loginUrl = $helper->getLoginUrl('**redacted**', $permissions);
    if(!isset($_SESSION['role'])){
        echo '<a href="' . $loginUrl . '">Log in with Facebook!</a>';
    }
?>
{% endhighlight %}
With the application secret, I could make calls to Facebook Graph API on behalf of the application, potentially violating privacy of its users.

## Take-away so far
* Never place **SECRETS/PASSWORDS** in the backend code itself, place them into the environment variables or in a file in another directory which no one can view except root/web-user, and make sure the file is not in your **GIT** repository.
* Never use simple passwords, gosh it's not like you're going to enter these passwords everyday, please use something stronger and randomly generated. In this case, the passwords were really simple and short.
* Do not ever ever ever `git clone` directly into your webserver's public directory (We saw why now). 
* Never ever ever expose your MySQL service to the public.

Thanks to the exposed MySQL service, I can now login directly to the DB and enumerate every piece of user data they have (I didn't).  
Next step, obviously I'll be trying the same password on their root account of the SSH service. 

![](/resources/images/dota/ssh.png)

Hurray! root access! Did you also notice that their server hasn't been updated for a while.

What did they do wrong? Many areas!

1. Never enable passwords for SSH login (especially if you're hosting with [Digital Ocean](https://news.ycombinator.com/item?id=7354289)). Use SSH keys instead, enabling passwords is bad when you have short passwords. Read [here](https://www.digitalocean.com/community/tutorials/how-to-set-up-ssh-keys--2) for steps to enable SSH keys.  
2. Never ever ever re-use passwords.  
3. Never ever ever allow login to root accounts. Always let users get elevated privileges through `sudo`, which an administrator could control more discretely/fine-grained.  
4. Update your server regularly!

Like many has said, all you need is one weak spot in order for an adversary to enter your system. Even if I did not manage to enter the server through SSH, I could easily pivoted from the Database servers by spawning a reverse shell or planting a backdoor onto their server.

# Conclusion
There are many different possible vulnerabilities that might exist on a website and it takes concious effort in order to discover and patch them. However, common vulnerabilities like those mentioned should have been detected earlier and removed. Hopefully this post will help introduce some concept of security as well as some technical details that you might not have known before.

I'd like to iterate that the post is not to shame anyone of the 12 applications and I'd also like to take the chance to thank Dr. Steven Halim for giving me the chance to audit them. :P




