---
layout: post
title: SECUINSIDE CTF Quals 2016 - Trendyweb
modified:
categories: blog
excerpt: ""
tags: []
image:
  feature:
share: true
comments: true
date: 2016-07-10T21:46:07+02:00
---

# SECUINSIDE CTF Quals 2016 - Trendyweb
>**Points:** 100  
**Category:** Web  
**Description**  
Trendy~! Web~  
The flag reader is on /.  
[http://chal.cykor.kr:8082](http://chal.cykor.kr:8082)  
[http://52.78.11.234:8082](http://52.78.11.234:8082)  
p.s. If the download doesn't work, try this: [https://gist.github.com/Jinmo/e49dfef9b7325acb12566de3a7f88859](https://gist.github.com/Jinmo/e49dfef9b7325acb12566de3a7f88859)  
and it requires data/ folder

---

We're given the source code for the challenge:

{% highlight php linenos %}
<?php
error_reporting(E_ALL);
ini_set('display_errors', 'On');
ini_set('allow_url_fopen', 'On'); // yo!

$session_path = '';

    class MyClass { function __wakeup() { system($_GET['cmd']); // come onn!
    } }

    function onShutdown() {
        global $session_path;
        file_put_contents($session_path. '/pickle', serialize($_SESSION));
    }

    session_start();
    register_shutdown_function('onShutdown');

    function set_context($id) {
        global $_SESSION, $session_path;

        $session_path=getcwd() . '/data/'.$id;
        if(!is_dir($session_path)) mkdir($session_path);
        chdir($session_path);

        if(!is_file('pickle')) $_SESSION = array();
        else $_SESSION = unserialize(file_get_contents('pickle'));
    }

    function download_image($url) {
        $url = parse_url($origUrl=$url);
        if(isset($url['scheme']) && $url['scheme'] == 'http')
            if($url['path'] == '/avatar.png') {
                system('/usr/bin/wget '.escapeshellarg($origUrl));
            }
    }

    if(!isset($_SESSION['id'])) {
        $sessId = bin2hex(openssl_random_pseudo_bytes(10));
        $_SESSION['id'] = $sessId;
    } else {
        $sessId = $_SESSION['id'];
    }
    session_write_close();
    set_context($sessId);
    if(isset($_POST['image'])) download_image($_POST['image']);
?>

<img src="/data/<?php echo $sessId; ?>/avatar.png" width=80 height=80 />
{% endhighlight %}

This appears to be a very straightforward challenge. It's a simple service, you're given a session id and you can upload an image through a URL using `$_POST['image']`,which is stored in a directory named using the session id.

The first thing that caught my attention was the `wget` call. Just few days ago, a wget [vulnerability](http://legalhackers.com/advisories/Wget-Arbitrary-File-Upload-Vulnerability-Exploit.txt) was publicly disclosed, one that would allow arbitrary files to be downloaded.

Also, notice that there is an unserialize call at the start of the script using the contents from a file named `pickle`. It is important to also see that there is a small class called `MyClass` that would allow us to invoke arbitrary PHP commands through the `$_GET['cmd']` parameter.

The attack sequence is now obvious:

1. Make a **POST** request to the service with a URL (path needs to be `/avatar.png`) as the value of `$_POST['image']`.
2. Redirect any requests made to the URL to a FTP URL with a file named `pickle`.
3. Invoke `set_context` that in turns unserializes the content in `pickle` and now we have arbitrary PHP code execution.

What is not obvious here is:

1. A shutdown function is registered, right before the end of the PHP script execution, the `pickle` file will be overwritten with the value from `serialize($_SESSION)`.
2. `set_context` is called only at the start of the PHP script execution, that means we won't be able to perform step #3 after step #1 of the attack sequence (assuming a single request).

What could be done instead is to cause a race-condition by doing two requests in parallel. First, make a **POST** request to the service in order to get arbitrary content in `pickle`. The payload for `pickle` is `O:7:"MyClass":0:{}`, which is the serialized form for `MyClass`. Second, when the file is saved onto the remote service and before it is overwritten by the shutdown function, make a second request that invokes `set_context`, which then runs the arbitrary PHP code specified through `$_GET['cmd']`.

It can be tricky to invoke the race-condition, and takes a few attempts. After some attempts, the flag can be obtained from running the binary at `/flag_is_heeeeeeeereeeeeee`. 

### Other ways
I personally believe the originally intended method by the challenge setter was the above with the race-condition. However, I also found that there are slightly easier ways to get the flag without having to invoke the race-condition. 

#### Method #1
The folder that the `pickle` file is saved does not seem to have PHP disabled, so what could be done instead is to redirect the HTTP request to a FTP URL with a PHP script. The PHP script could be a simple `<? passthru($_GET['cmd']) ?>` that allows us to run arbitrary PHP commands.

This would be obviously way less tedious than the above-mentioned method.

#### Method #2
The check here `if($url['path'] == '/avatar.png')` doesn't take into account for query parameters and so it is possible to specify a URL like `avatar.png%3fcmd.php` which is decoded to `avatar.png?cmd.php`, which is saved as a .php file and executes PHP instructions when browsed.  
*** Only found out this method after viewing the write up by team p4 [here](https://github.com/p4-team/ctf/tree/master/2016-07-09-secuinside-ctf/trendyweb).