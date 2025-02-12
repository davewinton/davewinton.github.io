---
layout: post
title: Decipher It! - Reverse Engineering the now Abandoned 'encipher.it' Web Encryption Tool
author: Dave Winton
category: cybersecurity 
feature-img: "assets/img/pexels/Network.jpg"
tags: [cybersecurity, encryption]
excerpt_separator: <!--more-->
---

## What was encipher.it?

**EncipherIt** was a web-based encryption/decryption tool which could be used to encrypt text and files inside a web browser. As of 2025, the site no longer exists but is fully accessible from the Internet Archive's **Wayback Machine**.
<!--more-->
The Wayback Machine has the first snapshot of the site taken on **2011-06-17** but the website itself mentions earlier versions so I can't be completely sure of its age.

![encipher.it homepage](/assets/img/encipherit/encipherit-homepage.png)

**Table of Contents:**
- [What was encipher.it?](#what-was-encipherit)
  - [Bookmarklets and the Early Versions of encipher.it](#bookmarklets-and-the-early-versions-of-encipherit)
- [Examining inject.v2.js](#examining-injectv2js)
    - [Key Points of Concern](#key-points-of-concern)
- [Reverse Engineering the Crypto System](#reverse-engineering-the-crypto-system)
  - [Motivation](#motivation)
  - [Exploring the Wayback Machine](#exploring-the-wayback-machine)
  - [Cryptography](#cryptography)
  - [Encryption and Ciphertext](#encryption-and-ciphertext)
- [Quirks and Failures](#quirks-and-failures)
  - [HMAC\_SHA1](#hmac_sha1)
  - [Salt creation](#salt-creation)
  - [Key Derivation](#key-derivation)
    - [PBKDF2](#pbkdf2)
    - [Key Derivation Process](#key-derivation-process)
    - [Flaws in Key Handling](#flaws-in-key-handling)
- [AES Specifics](#aes-specifics)
  - [What is CTR Mode?](#what-is-ctr-mode)
  - [Counter Mode and Nonce/IV generation](#counter-mode-and-nonceiv-generation)
- [Building decipher.it.py](#building-decipheritpy)
  - [Cryptography](#cryptography-1)
  - [Extracting the decryption parameters from ciphertext](#extracting-the-decryption-parameters-from-ciphertext)
- [Where can I find decipher.it.py?](#where-can-i-find-decipheritpy)
- [Attacking ciphertext to reveal time of creation](#attacking-ciphertext-to-reveal-time-of-creation)
  - [So what can you do with a timestamp?](#so-what-can-you-do-with-a-timestamp)
- [Mitigation Recommendations](#mitigation-recommendations)
- [Closing Thoughts](#closing-thoughts)

Searching through the first iterations of the site, it appears that it was originally intended to be used as a JavaScript bookmarklet which could encrypt/decrypt text on the fly for email or anything else. Later on the bookmarklet version was removed and the website simply provided a textbox for encryption. The final iteration of the **EncipherIt** product lineup was standalone software that used GPG encryption. 

![encipher.it bookmarklet usage](/assets/img/encipherit/encipherit-earlyusage.png)

For this write-up, I'll focus on the **web version** of the service, as it is no longer available online and is now accessible only via the **Wayback Machine**. There is a risk that it may eventually vanish from the internet altogether so my hope was to build an easy decryption tool in Python in case it's ever needed by users of the site.

### Bookmarklets and the Early Versions of encipher.it

Bookmarklets are small JavaScript programs stored as browser bookmarks. When clicked, they execute code directly in the user's browser. This was a common way to extend browser functionality before browser extensions became widespread.

The following link was the bookmarklet users save to use the **EncipherIt** encryption tool:

```javascript
javascript:(function(){document.body.appendChild(document.createElement('script')).src='https://encipher.it/javascripts/inject.v2.js';})();

```

## Examining inject.v2.js

Let's take a deeper look at `inject.v2.js`:

```javascript
(function() {
  var BASE_URL, startup,
    __indexOf = [].indexOf || function(item) { for (var i = 0, l = this.length; i < l; i++) { if (i in this && this[i] === item) return i; } return -1; };

  BASE_URL = "https://encipher.it";

  startup = function() {
    var count, ready, script, script_tag, scripts, _i, _len, _results;
    if (window.encipher) {
      return window.encipher.startup();
    }
    scripts = ['encipher.js', 'AES.js', 'sha1.js', 'pbkdf2.js', 'base64.js', 'utf8.js'];
    if (typeof jQuery === "undefined") {
      scripts.push('jquery.min.js');
    }
    count = scripts.length;
    ready = function() {
      count -= 1;
      if (count === 0) {
        if (__indexOf.call(scripts, 'jquery.min.js') >= 0) {
          $.noConflict();
        }
        jQuery.expr[':'].focus = function(elem) {
          return elem === document.activeElement && (elem.type || elem.href);
        };
        window.encipher = new Encipher(BASE_URL);
        return window.encipher.startup();
      }
    };
    _results = [];
    for (_i = 0, _len = scripts.length; _i < _len; _i++) {
      script = scripts[_i];
      script_tag = document.createElement('script');
      script_tag.setAttribute("type", "text/javascript");
      script_tag.setAttribute("src", BASE_URL + "/javascripts/" + script);
      script_tag.onload = ready;
      script_tag.onreadystatechange = function() {
        if (this.readyState === 'complete' || this.readyState === 'loaded') {
          return ready();
        }
      };
      _results.push(document.getElementsByTagName("head")[0].appendChild(script_tag));
    }
    return _results;
  };

  startup();

}).call(this);
```

The script has several interesting areas to probe for weaknesses, as it dynamically loads several JavaScript files that will handle various aspects of the encryption process.

#### Key Points of Concern

1. **Multiple Unverified Scripts:**  
    Several unverified scripts are being loaded and executed. If the site were to be compromised, malicious code could be inserted into any of these scripts without any further checks, potentially compromising users’ data.
2. **Dynamic Script Injection:**  
    The `document.createElement('script')` method is used to inject scripts into the webpage. This dynamic approach means there's no integrity check to ensure the scripts haven’t been tampered with. If an attacker were able to compromise the website, they could inject malicious code into any of the scripts and it would be executed on the user's machine.
3. **Vulnerable jQuery version:** The site uses v2.4.2 which is vulnerable to several XSS attacks. 

## Reverse Engineering the Crypto System

So bookmarklets aside, let's get to the main point of this post, the crypto system. 

### Motivation

I had never personally used or heard of **EncipherIt** until I encountered it in a **cybersecurity class** with a packet tracer lab exercise which tasked me to decrypt a provided ciphertext using the **EncipherIt** website.

When I attempted to visit the website, it became clear that the service was no longer available, and the domain now redirects to a shady list of crypto casino websites. So unable to complete the lab, I decided to reverse-engineer the system to understand how it worked and see if building a decryption tool was feasible. It seemed like a fun project to do over the weekend. 

![encipher.it gone](/assets/img/encipherit/encipherit-gone.png)

Below is the provided ciphertext and password for the Packet Tracer lab exercise **2.5.2.6**:

```
ciphertext = "EnCt2488820db35158fbdc834a1b388154e9da202d78a488820db35158fbdc834a1b3f8crayX4lQBB3aQqQVeg8VuPECZzaFM/CkvuMmYk9TAEBGJA4IsvBfce/mB0HSjZ1DdOZovP36o500VmbBsqG86YGmX3siG8ZA==IwEmS"
password = "maryftp123" 
```

![Packet Tracer problem](/assets/img/encipherit/encipherit-packettracer.png)

As a cryptography enthusiast, I took it upon myself to investigate how **EncipherIt** worked and if I could rebuild the decryption process and spent an entire weekend debugging and investigating it's secrets.

### Exploring the Wayback Machine

To start my investigation, I returned to the **Wayback Machine**, where I found years of working versions of the **EncipherIt** website. Through this, I could examine the JavaScript files and reverse-engineer the underlying crypto system. In fact, the website is still fully functional through the Wayback Machine, so I probably could have called it a day there, but where is the fun in that?

The screenshot below shows several files that required further investigation:
- inject.v2.js
- AES.js
- base64.js
- encipher.js
- pbkdf2.js
- sha1.js
- utf-8.js

![encipher.it javascript](/assets/img/encipherit/encipherit-js.png)

### Cryptography

The cryptography used in the **EncipherIt** crypto system seems to be pieced together from tools written by other programmers, many of which date back 15-20 years ago (or longer). One interesting thing I came across while researching this tool was discovering the GitHub of the author behind the `AES.js` script.

This particular AES implementation was written by [Chris Veness](https://github.com/chrisveness/crypto), who last updated the repo around 5 years ago (as of February 2025). In the README, he mentions:

_"Cryptographically speaking, browsers are inherently insecure (Node.js does not suffer the same problems), but these implementations are intended for study rather than production use."_

During my reverse engineering of **EncipherIt**, I found this statement to be all too true. Chris’s implementation works in the sense that it produces and decrypts ciphertext as needed, but it’s not a secure solution and doesn’t follow any best practices that modern cryptography libraries would require. 

This is further complicated by the way **EncipherIt** handles encryption and decryption, which veers into non-standard and, frankly, bad cryptographic practices at times.

There are several oddities hidden in the site’s code and design choices, which make decrypting **EncipherIt** ciphertext tricky. Since I was spending all this time learning how the system works, I figured I'd share my research. 

So, let’s dive in!

### Encryption and Ciphertext

To begin our analysis, let's start with how **EncipherIt** handles encryption of plaintext.

![encipher.it Aes.Ctr.encrypt](/assets/img/encipherit/encipherit-encrypt.png)

```javascript
Encipher.prototype.encrypt = function(password, callback) {
  var salt,
	_this = this;
  salt = Base64.random(8);
  return this.derive(password, salt, function(key) {
	var cipher, hmac;
	hmac = hex_hmac_sha1(key, _this.text);
	hmac += hmac.slice(0, 24);
	cipher = hmac + salt + Aes.Ctr.encrypt(_this.text, key, 256);
	return _this.format.text.pack("EnCt2" + cipher + "IwEmS", function(error, cipher) {
	  if (!error) {
		_this.updateNode(_this.node, cipher);
	  }
	  _this.cache = {};
	  return callback(error, cipher);
	});
  });
};
```

As you can see, it all looks pretty standard. It takes a password as an input parameter, generates a salt, derives some keys, generates a HMAC_SHA1 digest from the key and data, and finally calls `Aes.Ctr.encrypt`.

The output then prepends and appends some identifiers (`EnCt2` and `IwEmS`) to the ciphertext which **EncipherIt** uses to determine if the input is valid ciphertext during decryption.

The ciphertext below was encrypted using the **EncipherIt** encryption tool with the following parameters:
- **Plaintext:** "Hello World"
- **Password:** "password"
- **Date encrypted:** 2025-02-09

Output: 
```
"EnCt2bbd78913842cb78ca77c4bcf85e8df078858cb77bbd78913842cb78ca77c4bcfrnzIvb9CBgCfrLT/p2f5l+wqR6Q4DhSRCg==IwEmS"
```

Remember this, as I will be using and referencing it later in this paper.

The ciphertext has the following format as seen in the encrypt function above:

| Name                     | Content                                  | Size                             | Index |
| ------------------------ | ---------------------------------------- | -------------------------------- | ----- |
| Prefix                   | EnCt2                                    | 5 characters                     | 0:5   |
| HMAC_SHA1                | bbd78913842cb78ca77c4bcf85e8df078858cb77 | 40 characters (hex) <br>20 bytes | 5:45  |
| HMAC_SHA1 <br>(repeated) | bbd78913842cb78ca77c4bcf                 | 24 characters (hex) <br>12 bytes | 45:57 |
| Salt                     | rnzIvb9C                                 | 8 characters (b64)               | 57:65 |
| Ciphertext               | BgCfrLT/p2f5l+wqR6Q4DhSRCg==             | Variable length (b64)            | 65:X  |
| Suffix                   | IwEmS                                    | 5 characters                     | X:X+5 |

As you can see, this format combines ASCII, base64, and hex-encoded values into a single output string. 

The **ciphertext** is then broken down into two parts:

- **Nonce/IV:** 8 bytes
- **Actual ciphertext:** All remaining bytes

## Quirks and Failures

Before we proceed, I need to discuss many of the oddities and deviations from standard implementations which **EncipherIt** uses in its crypto-system.

Let’s take a look at some of these peculiarities and discuss why they make it unsuitable for production or serious cryptographic use.

### HMAC_SHA1

The standard output for a HMAC_SHA1 digest is 20 bytes (or 40 hex characters). However, for reasons unknown to me, **EncipherIt** appends the first 12 bytes of the HMAC to the end, resulting in a total of 32 bytes (64 hex characters).

In my testing, I could never figure out why this was done. After reviewing both earlier and later versions of the `Encipher.prototype.decrypt` function through the **Wayback Machine**, it seems even the developer might not have understood what they were trying to implement.

Here’s a snippet from the earlier version of the decryption functions which shows how the HMAC verification is handled:

```javascript
Encipher.prototype.decryptNode = function(node, text, password, callback) {
      var _this = this;
      return this.unpack(text, function(error, text) {
        var hash, hmac, salt;
        if (error) {
          return callback(error, false);
        }
        _this.updateNode(node, text);
        text = text.slice(5, text.length - 5);
        hash = text.slice(0, 64);
        hmac = text.slice(0, 40);
        salt = text.slice(64, 72);
        text = text.slice(72);
        return _this.derive(password, salt, function(key) {
          text = Aes.Ctr.decrypt(text, key, 256);
          if (hex_hmac_sha1(key, text) === hmac || hash === Sha256.hash(text)) {
            _this.updateNode(node, text);
            return callback(null, true);
          } else {
            return callback(null, false);
          }
        });
      });
    };

    Encipher.prototype.decrypt = function(password, callback) {
      var i, next, success,
        _this = this;
      i = 0;
      success = false;
      next = function() {
        if (_this.nodes.length > i) {
          return _this.decryptNode(_this.nodes[i], _this.texts[i], password, function(error, res) {
            if (error) {
              return callback(error, false);
            }
            i += 1;
            success || (success = res);
            return next();
          });
        } else {
          _this.cache = {};
          return callback(null, success);
        }
      };
      return next();
    };
```
 
 Pay particular attention what is happening with the HMAC verification during decryption.

```javascript
if (hex_hmac_sha1(key, text) === hmac || hash === Sha256.hash(text))
```

Remember, `hmac` is the first 64 characters (32 bytes) after the prefix, which consists of the original `hmac` plus the first 12 bytes of the same `hmac` concatenated onto the end. 

`sha256` on the plaintext never actually occured, so how could `hash === Sha256.hash(text)` ever evaluate to `true`?

While this `OR` condition was removed in later versions, the fundamental issue with HMAC verification and how it's handled by **EncipherIt** remains a mystery to me.

I spent some time debugging the old website with browser dev tools to examine the exact input/output values during encryption. After comparing the results, I found that for:

- **Data:** "Hello World"
- **Key:** "3e6b695f3eb72bf95fa9868b329698a2db05b5087737cbb4d6d40292db8b9bce"

The generated **HMAC_SHA1** from **EncipherIt** is: "77542d402ff09771c84e36f1bc34b6e69af7390b77542d402ff09771c84e36f1". 

If we removed the added 24 characters we then arrive at:
- **HMAC_SHA1:** "77542d402ff09771c84e36f1bc34b6e69af7390b"

I ran this the same key and data through Python and PowerShell (shown below) HMAC_SHA1 implementations, and they both produced different (but valid) outputs, confirming that the issue lies with the **EncipherIt** implementation. It possible that **EncipherIt** is using an outdated or incorrectly implemented version of `HMAC_SHA1`.

```powershell
# PowerShell HMAC_SHA1 
# Define the text and key (hex)
$text = "Hello World"
$keyHex = "3e6b695f3eb72bf95fa9868b329698a2db05b5087737cbb4d6d40292db8b9bce"

# Convert the key from hex to byte array
$keyBytes = [System.Convert]::FromHexString($keyHex)

# Create an instance of the HMACSHA1 class
$hmacsha1 = New-Object System.Security.Cryptography.HMACSHA1
$hmacsha1.Key = $keyBytes

# Compute the HMAC
$hmacBytes = $hmacsha1.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($text))

# Convert the result to a hex string
$hmacHex = [BitConverter]::ToString($hmacBytes) -replace '-'

# Output the result
Write-Host "HMAC-SHA1: $hmacHex"

HMAC-SHA1: 7ED6EF7ABB12597276BDA5403ABB85BB4E6CD93A
```

and as a sanity check, the same thing in python. 

```python
# Python HMAC_SHA1
from Crypto.Hash import HMAC, SHA1

text = "Hello World"
key_hex = "3e6b695f3eb72bf95fa9868b329698a2db05b5087737cbb4d6d40292db8b9bce"
hmac_sha1 = HMAC.new(bytes.fromhex(key_hex), text.encode('utf-8'), digestmod=SHA1).hexdigest()
print (f"HMAC-SHA1: {hmac_sha1}")

HMAC-SHA1: 7ed6ef7abb12597276bda5403abb85bb4e6cd93a
```

Both Python and PowerShell output the same value `7ed6ef7abb12597276bda5403abb85bb4e6cd93a` which does not match the **EncipherIt** value of `77542d402ff09771c84e36f1bc34b6e69af7390b`

### Salt creation

The salt used for PBKDF2 key derivation is generated by the following function in `base64.js`:
 
```javascript
Base64.random = function(len) {
    var text = "";
    for( var i=0; i < len; i++ )
            text += Base64.code.charAt(Math.floor(Math.random() * Base64.code.length));
    return text;
}
```

An 8-character Base64-encoded string has 48 bits of entropy (6 bits per character) and allows for 2^48 unique salts, which is generally considered "secure enough."

The crucial thing to note here is that the salt is processed as Base64 during the key derivation process, and not as decoded Base64. 

Any other method will produce incorrect keys, leading to failed decryption.

To show this in Python:

```python
salt = "rnzIvb9C".encode() # Do this
salt = base64.b64decode("rnzIvb9C") # Don't do this
```

### Key Derivation

#### PBKDF2
**EncipherIt** uses `pbkdf2.js` for key derivation (version 1.1, copyright 2007, **Parvez Anandam**). 

However, it uses an insecure and insufficient number of iterations (1000) when deriving the key.

While this tool and website was developed over 15 years ago, standards have evolved. 

What was once considered strong is now inadequate for defending against modern brute force attacks. Even at the time, recommendations for offline encryption (data-at-rest) suggested a much higher number of iterations to future-proof the system. The low iteration count here weakens the derived key and exposes the system to brute-force through the use of modern computational power.

#### Key Derivation Process

The key derivation process in **EncipherIt** involves an extra step that affects how keys are managed during encryption. After generating the key using `pbkdf2.js`, the encryption and decryption function in `AES.js` is called, which applies an additional key derivation step using AES-ECB to encrypt the PBKDF2 `derived_key`

Here’s the relevant code from `AES.js`:

```javascript
  // use AES itself to encrypt password to get cipher key (using plain password as source for key 
  // expansion) - gives us well encrypted key (though hashed key might be preferred for prod'n use)
  var nBytes = nBits/8;  // no bytes in key (16/24/32)
  var pwBytes = new Array(nBytes);
  for (var i=0; i<nBytes; i++) {  // use 1st 16/24/32 chars of password for key
    pwBytes[i] = isNaN(password.charCodeAt(i)) ? 0 : password.charCodeAt(i);
  }
  var key = Aes.cipher(pwBytes, Aes.keyExpansion(pwBytes));  // gives us 16-byte key
  key = key.concat(key.slice(0, nBytes-16));  // expand key to 16/24/32 bytes long
```

This approach is puzzling. Let's dig deeper:
- **`var nBytes = nBits/8;`**: Converts the key size (in bits) into bytes.
- **`var pwBytes = new Array(nBytes);`**: Initializes an array to hold the password's byte representation.
- **`for (var i = 0; i < nBytes; i++) { ... }`**: Loops through each byte of the password and converts it into a byte array.
- **`pwBytes[i] = isNaN(password.charCodeAt(i)) ? 0 : password.charCodeAt(i);`**: Converts the password characters into byte values, with a fallback if an invalid character is encountered.
- **`var key = Aes.cipher(pwBytes, Aes.keyExpansion(pwBytes));`**: Uses AES to encrypt the password bytes and expand the key.
- **`key = key.concat(key.slice(0, nBytes-16));`**: Extends the key to the desired length by concatenating part of the key to itself.

#### Flaws in Key Handling

I can only guess (based on the comments in the code) that the `AES.js` implementation handled deriving its own keys as a method to ensure inputted passwords are the correct length when they are fed in to the encrypt/decrypt functions. As the comment mentions it is not suitable for production use, but this is how **EncipherIt** handled keys in the encryption process.

The major issue here is that this process completely invalidates the PBKDF2-derived key generated in the previous step. 

Once the PBKDF2 key is fed into the AES-ECB operation, it is effectively overridden and replaced by the 16-byte AES output, which is then concatenated to itself to generate the final key used to actually encrypt the data. This makes the initial PBKDF2 derivation redundant and overall weakens the security of the system. 

The PBKDF2 key is never actually used for encryption and the much weaker AES derived key reduces the effective strength of the system to that of AES128 since the key is just the same 16-bytes concatenated to itself.

## AES Specifics 

**EncipherIt** uses AES256-CTR to encrypt/decrypt data. For those unfamiliar with the various **modes of operation** for block ciphers like AES, I will discuss the security required for CTR. 

### What is CTR Mode?

Counter (CTR) mode transforms a block cipher into a stream cipher. Here's a helpful excerpt from the Wikipedia page on [Counter (CTR) mode](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Counter_\(CTR\)):

_"Like OFB, counter mode turns a [block cipher](https://en.wikipedia.org/wiki/Block_cipher) into a [stream cipher](https://en.wikipedia.org/wiki/Stream_cipher). It generates the next [keystream](https://en.wikipedia.org/wiki/Keystream) block by encrypting successive values of a "counter". The counter can be any function that produces a sequence which is guaranteed not to repeat for a long time, although an actual increment-by-one counter is the simplest and most popular."_

In simpler terms, CTR mode relies on a **nonce (or IV)** that must never repeat for two messages. This might seem straightforward, but as it turns out, using a something like a simple timestamp as a nonce can lead to some serious vulnerabilities if implemented in the wrong way.

### Counter Mode and Nonce/IV generation

Below is the implementation for nonce generation in `AES.js`

```javascript
  // initialise 1st 8 bytes of counter block with nonce (NIST SP800-38A §B.2): [0-1] = millisec, 
  // [2-3] = random, [4-7] = seconds, together giving full sub-millisec uniqueness up to Feb 2106
  var counterBlock = new Array(blockSize);
  
  var nonce = (new Date()).getTime();  // timestamp: milliseconds since 1-Jan-1970
  var nonceMs = nonce%1000;
  var nonceSec = Math.floor(nonce/1000);
  var nonceRnd = Math.floor(Math.random()*0xffff);
  
  for (var i=0; i<2; i++) counterBlock[i]   = (nonceMs  >>> i*8) & 0xff;
  for (var i=0; i<2; i++) counterBlock[i+2] = (nonceRnd >>> i*8) & 0xff;
  for (var i=0; i<4; i++) counterBlock[i+4] = (nonceSec >>> i*8) & 0xff;
  
  // and convert it to a string to go on the front of the ciphertext
  var ctrTxt = '';
  for (var i=0; i<8; i++) ctrTxt += String.fromCharCode(counterBlock[i]);
```

Any keen observer will notice that this is using the current timestamp since epoch (1-Jan-1970) and doing some simple processing to output an 8-byte IV/Nonce.

- **Nonce Construction**: The nonce is created using the current timestamp (milliseconds since the Unix epoch), along with a random 16-bit value.
- **Combining the Nonce**: The timestamp is split into two parts—milliseconds (`nonceMs`) and seconds (`nonceSec`)—while the random value (`nonceRnd`) adds some variability.

This nonce generation scheme **weakens the security** of AES-CTR mode because it significantly reduces the entropy of the nonce. 

To understand why we need to discuss what this does wrong. 

- The **timestamp (`nonce`) is derived from the current time** in milliseconds since 1970. This makes the nonce highly predictable, as an attacker can estimate the time a message was encrypted.
- The **second part (`nonceSec`) is 32 bits**, with a range of values from 0-2^32
- The **millisecond part (`nonceMs`) is only 16 bits (0–999)**, meaning there are at most **1,000 possibilities** for this component represent as a 2 byte value.
- The **random portion (`nonceRnd`) is only 16 bits (0–65535)**, meaning there are at most **65,536 possible values**.

It should be said the bit values above **are not a measure of entropy**, simply the size of each chunk of the IV. 

The `timestamp` itself is the basis of the nonce generation, as both `nonceMs` and `nonceSec` are derived from it, but the only randomness is a 16-bit value generated by a non-CSRNG.

So why does this matter?

To say it plainly, this is not enough randomness to ensure the security of AES-CTR. The IV/nonce should ideally be 8 cryptographically **random** bytes from a source with high entropy. The use of a timestamp also opens up various methods of attacking the ciphertext via the nonce. We can even use this to find the time of creation (which I go into later in this report).

As I discussed above, the security of CTR mode depends on no two encrypted texts ever sharing an IV, but through this system, it is possible (however unlikely) that two users could encrypt an input at the exact same time, and the only randomness added would be the 2 "random" bytes. 

For what **EncipherIt** was and the size of the userbase who made user of this tool, this is probably fine, but for serious cryptography use this would be unacceptable. 

## Building decipher.it.py

So now we have learned about the inner workings of **EncipherIt**, we can start to implement a solution for decrypting the ciphertexts it makes. 

### Cryptography

The first step is to define all the crypto primitives and ciphers that will be required for decryption.

```python
# === Key Derivation (PBKDF2-SHA1) ===
def derive_hmac_key(password, salt, iterations=1000, dklen=32):
    """Derive an HMAC key using PBKDF2-SHA1."""
    return hashlib.pbkdf2_hmac('sha1', password.encode(), salt, iterations, dklen)

# === AES Key Derivation (From Derived Key) ===
def derive_aes_key(derived_key):
    """
    Derives an AES key from the derived key (hexstring) by converting it to Unicode
    values and encrypting using AES-ECB mode.
    The final 32-byte AES key is generated using the first 16 bytes of the encryption result.
    """
    unicode_values = [ord(c) for c in derived_key.hex()]  # Convert hexstring to Unicode values
    return aes_ecb_encrypt(bytes(unicode_values[:32]))

# === AES Decryption (AES-256-CTR) ===
def aes_ctr_decrypt(ciphertext, key, nonce):
    """Decrypt the ciphertext using AES-CTR mode with the given key and nonce."""
    cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
    return cipher.decrypt(ciphertext)

# === AES Encryption (AES-256-ECB) ===
def aes_ecb_encrypt(key: bytes) -> bytes:
    """Encrypt the provided key using AES in ECB mode and derive a 32-byte AES key."""
    cipher = AES.new(key, AES.MODE_ECB)
    encrypted_key = cipher.encrypt(key)
    return bytes(encrypted_key[:16] + encrypted_key[:16])  # Duplicate the first 16 bytes
```

Most of this follows standard cryptographic practices, but one part deserves special attention:

```python
unicode_values = [ord(c) for c in derived_key.hex()]  # Convert hexstring to Unicode values
```

At first glance, this might seem like a trivial conversion, but it was one of the trickiest steps in the entire decryption process. What happens here is: 

**As the PBKDF2-derived `derived_key` is fed into the AES-ECB function to derive the `aes_key`, it’s not interpreted as a byte array (which would have been straightforward). Instead, the derived key is first converted to its hex representation, then each character in that hex string is mapped to its ordinal value.**

the `ord` function in python returns the Unicode code for a given character. 

For example: `ord('a') = 97`, `ord('b') = 98` .. and so on.

So its not the byte value or the hex representation of the byte value used in the **EncipherIt** derivation of `aes_key`. These values can be shown in python:

```python
>>> 'a'.encode() # incorrect
b'a'
>>> 'a'.encode().hex() # incorrect
'61'
>>> ord('a') # correct
97
```

Any other method of feeding the `derived_key` into the AES-ECB encryption key derivation process produces the wrong keys for decryption. 

If we look at the `derived_key` for the demo ciphertext:

```python
>>> derived_key = "77b8f02a2a2a003b27954ca85611639de35e43f560ec2514391bd2228ace66c3"
>>> bytes.fromhex(derived_key)
# Output: 
b'w\xb8\xf0***\x00;\'\x95L\xa8V\x11c\x9d\xe3^C\xf5`\xec%\x149\x1b\xd2"\x8a\xcef\xc3'
```

Neither of these produce the correct `aes_key`. The required format to generate the correct `aes_key` would be:

```python
[ord(c) for c in '77b8f02a2a2a003b27954ca85611639de35e43f560ec2514391bd2228ace66c3']
# Output:
# Values: ord('7') = 55, ord('7') = 55, ord('b') = 98 .. and so on 
[55, 55, 98, 56, 102, 48, 50, 97, 50, 97, 50, 97, 48, 48, 51, 98, 50, 55, 57, 53, 52, 99, 97, 56, 53, 54, 49, 49, 54, 51, 57, 100, 101, 51, 53, 101, 52, 51, 102, 53, 54, 48, 101, 99, 50, 53, 49, 52, 51, 57, 49, 98, 100, 50, 50, 50, 56, 97, 99, 101, 54, 54, 99, 51]
```

For completeness' sake, I include this here in the hope that it might prove useful (or at least interesting) to the reader.

As I discussed in the Key Derivation sections above, the `aes_key` is an extreme oddity and reduces the overall security of the entire crypto system, the result of which can be seen plainly in the return value of `aes_ecb_encrypt`.

```python
return bytes(encrypted_key[:16] + encrypted_key[:16])  # Duplicate the first 16 bytes
```

This effectively reduces the key space by half, making brute-force attacks significantly easier.

### Extracting the decryption parameters from ciphertext

So now that the cryptography is setup, the next step is to parse the necessary information for decryption. 

Luckily, the `Aes.Ctr.decrypt` function in `AES.js` provided a clear roadmap, with the main challenge being the correct handling of encoding and decoding.

```python
# Set the PREFIX and SUFFIX
PREFIX = "EnCt2"
SUFFIX = "IwEmS"

# Check for valid ciphertext
if not enciphered_data.startswith(PREFIX) or not enciphered_data.endswith(SUFFIX):
	print("Invalid ciphertext format.")
	return None

# Strip the prefix and suffix
encrypted_message = enciphered_data[len(PREFIX):-len(SUFFIX)]

# Extract components from the encrypted message
hmac_key_hex = encrypted_message[:40]
salt = encrypted_message[64:72].encode()

# Parse the actual ciphertext
encrypted_data = base64.b64decode(encrypted_message[72:])
nonce = encrypted_data[:8]
ciphertext = encrypted_data[8:]
```

Next we need to derive both the `derived_key` and the `aes_key`

```python
# Derive keys using password and salt
derived_key = derive_hmac_key(password, salt)
aes_key = derive_aes_key(derived_key)
```

Finally, we can call our `aes_ctr_decrypt` function and recover the plaintext!

```python
# Decrypt the ciphertext
try:
	p_text = aes_ctr_decrypt(ciphertext, aes_key, nonce)
	if test_data:
		return p_text.decode()
except UnicodeDecodeError as e:
	print(f"[!] Error: {e}")
	return None
```

## Where can I find decipher.it.py?

You can see the entire script on my [GitHub](https://github.com/davewinton/decipherit), along with the other python scripts I have created and reference here.

The script also outputs a table (as shown below) which lists all decryption parameters (salt, nonce, both keys, ciphertext) which allows any modern AES-CTR implementation to decrypt the data without dealing with the quirks of this funny crypto system.

```shell
python3 decipher.it.py
[*] Gathering decryption parameters..
[*] Deriving keys..
+-------------+------------------------------------------------------------------+
| Parameter   | Value                                                            |
+=============+==================================================================+
| Salt        | rnzIvb9C                                                         |
+-------------+------------------------------------------------------------------+
| Nonce       | 06009facb4ffa767                                                 |
+-------------+------------------------------------------------------------------+
| DerivedKey  | 77b8f02a2a2a003b27954ca85611639de35e43f560ec2514391bd2228ace66c3 |
+-------------+------------------------------------------------------------------+
| AESKey      | 3eaaf3c83750a3d0082294a5ba8b12573eaaf3c83750a3d0082294a5ba8b1257 |
+-------------+------------------------------------------------------------------+
| HMAC_SHA1   | bbd78913842cb78ca77c4bcf85e8df078858cb77                         |
+-------------+------------------------------------------------------------------+
| Ciphertext  | f997ec2a47a4380e14910a                                           |
+-------------+------------------------------------------------------------------+
[*] Decrypting data..
[+] Decryption successful!


=== Decrypted Message ===
Hello World
```

All of the data in the hex string above "f997ec2a47a4380e14910a" is still encrypted, but it's now in a format which bypasses all the strange encoding/decoding issues of the **EncipherIt** system. 

Simply copy the `nonce`, `aes_key` and `ciphertext` hex strings and then they can easily be fed in AES-CTR by using:

```python
# pip install pycryptodome
from Crypto.Cipher import AES

def aes_ctr_decrypt(ciphertext, key, nonce):
    """Decrypt the ciphertext using AES-CTR mode with the given key and nonce."""
    cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
    return cipher.decrypt(ciphertext)

# Hexstrings containing decryption params
aes_key = "3eaaf3c83750a3d0082294a5ba8b12573eaaf3c83750a3d0082294a5ba8b1257"
nonce = "06009facb4ffa767"
ciphertext = "f997ec2a47a4380e14910a"

# Convert to bytes using fromhex()
key = bytes.fromhex(aes_key)
nonce = bytes.fromhex(nonce)
ctext = bytes.fromhex(ciphertext)

# AES-CTR Decryption
print(f"Deciphered Message: {aes_ctr_decrypt(ctext, key, nonce).decode()}")
```

Which should output:

```shell
python3 aes-ctr-decrypt.py
Deciphered Message: Hello World
```

## Attacking ciphertext to reveal time of creation

I thought it might be a good idea to show a possible attack on **EncipherIt** ciphertext. 

One of the most easily exploited weaknesses is the timestamp used as the nonce for CTR mode. For block ciphers like AES, IV/nonce values do not need to remain secret, in fact they are stored along with the ciphertext because without them, decryption is impossible. While the IV/nonce might not need to be be kept secret, they also shouldn't leak information about the encrypted message or **metadata**.

Metadata is most easily defined as "data about data". This includes things like title, author, file size and time of creation. You'll notice that one of those things are embedded into the ciphertext output of the **EncipherIt** crypto. 

**The timestamp**.

Since the timestamp is embedded in the ciphertext, we can reverse the process of how it was generated to gain access to the time of creation, with a reasonable degree of accuracy. 

In cryptanalysis, any information that reveals part of the cipher can be disastrous for the security of the cipher.

Let's try reversing the process on the test ciphertext generated from the plaintext `"Hello World":"password"` on `2025-02-09`.

Below is a table containing the output from my `decipher.it.py` script for the above ciphertext.

```shell
python3 decipher.it.py
[*] Gathering decryption parameters..
[*] Deriving keys..
+-------------+------------------------------------------------------------------+
| Parameter   | Value                                                            |
+=============+==================================================================+
| Salt        | rnzIvb9C                                                         |
+-------------+------------------------------------------------------------------+
| Nonce       | 06009facb4ffa767                                                 |
+-------------+------------------------------------------------------------------+
| DerivedKey  | 77b8f02a2a2a003b27954ca85611639de35e43f560ec2514391bd2228ace66c3 |
+-------------+------------------------------------------------------------------+
| AESKey      | 3eaaf3c83750a3d0082294a5ba8b12573eaaf3c83750a3d0082294a5ba8b1257 |
+-------------+------------------------------------------------------------------+
| HMAC_SHA1   | bbd78913842cb78ca77c4bcf85e8df078858cb77                         |
+-------------+------------------------------------------------------------------+
[*] Decrypting data..
[+] Decryption successful!


=== Decrypted Message ===
Hello World
```

Let's grab that `nonce` value and build `timegrabber.py` to try and extract it. This is the reverse process of the JavaScript in the `Aes.Ctr.encrypt` function shown in previous sections.

```python
import datetime

nonce= "06009facb4ffa767"

# Convert hex string to byte array
counterBlock = bytes.fromhex(nonce)

# Step 1: Reconstruct nonceMs (milliseconds)
nonceMs = (counterBlock[1] << 8) | counterBlock[0]

# Step 2: Reconstruct nonceRnd (random value)
nonceRnd = (counterBlock[3] << 8) | counterBlock[2]

# Step 3: Reconstruct nonceSec (seconds)
nonceSec = (counterBlock[7] << 24) | (counterBlock[6] << 16) | (counterBlock[5] << 8) | counterBlock[4]

# Step 4: Combine nonceSec and nonceMs to get the full timestamp (in milliseconds)
original_timestamp = nonceSec * 1000 + nonceMs

# Convert to human-readable UTC timestamp
dt = datetime.datetime.fromtimestamp(original_timestamp / 1000.0)

# Print the results
print(f"Reconstructed NonceMs: {nonceMs}")
print(f"Reconstructed NonceRnd: {nonceRnd}")
print(f"Reconstructed NonceSec: {nonceSec}")
print(f"Reconstructed Timestamp (milliseconds): {original_timestamp}")
print(f"Human-readable UTC timestamp: {dt}")
```

Output from `timegrabber.py`

```shell
Reconstructed NonceMs: 6
Reconstructed NonceRnd: 44191
Reconstructed NonceSec: 1739063220
Reconstructed Timestamp (milliseconds): 1739063220006
Human-readable UTC timestamp: 2025-02-09 11:37:00.006000
```

Success! We've managed to extract the exact time of creation (or close enough when accounting for rounding errors) to glean some very useful information about when this ciphertext was generated.

### So what can you do with a timestamp?

The ability to deduce the time of creation of a ciphertext could be particularly dangerous in facilitating targeted attacks. For example, if we know the ciphertext was generated at a specific time, an attacker could correlate that timestamp with real-world events or public records.

In a law-enforcement operation for example, if encrypted information is recovered and the timestamp is embedded in the ciphertext, it could potentially be used to link the data to a specific user or event. Simply having the time of creation could allow law enforcement to better target a suspect. This can be powerful information.

If an encryption system is used to protect sensitive communications or information, and the attacker knows the ciphertext was generated at a particular time, they could use public event logs, communications records, or even traffic analysis to infer who was likely involved, what was happening at that time, or how the encrypted data fits into a broader context.

This type of attack could also be used for **profiling** or **targeting individuals** by correlating encrypted data with known patterns of activity at certain times, essentially de-anonymizing or demasking the user who encrypted the data. An attacker could exploit this to infer sensitive information, track behaviours, or even identify time-based vulnerabilities based on the knowledge of when the ciphertext was created.

## Mitigation Recommendations

The failures of **EncipherIt** can easily be mitigated by implementing some modern values for key derivation and by removing the odd `aes_key` which replaces the `derived_key` in the final encryption. Below is a simple Python implementation which would be more secure while keeping the core functionality the same. 

1. `PBKDF2` iterations should be updated to modern standards (iterations=1000000)
2. `HMAC_SHA1` should be moved to a modern standard such as `HMAC_SHA512`
3. `nonce` and `salt` should be generated using a CSRNG with high sources of entropy
4. Skip the extra `aes_key` derivation and use the PBKDF2 `derived_key` directly for `AES-CTR`. 
5. Standardise encoding/decoding such that working with strings, hexstrings and bytes doesn't complicate decryption efforts. 

```python
from Crypto.Cipher import AES
from getpass import getpass
from os import urandom
import hashlib, hmac

# === Key Derivation (PBKDF2-SHA1) ===
def derive_hmac_key(password, salt, iterations=1000000, dklen=32):
    """Derive an HMAC key using PBKDF2-SHA1."""
    return hashlib.pbkdf2_hmac('sha512', password.encode(), salt, iterations, dklen)

# === Calculate HMAC (HMAC_SHA512) ===
def calc_hmac(key, data):
    return hmac.new(key, data, hashlib.sha512).digest()

# === AES Encryption (AES-256-CTR) ===
def aes_ctr_encrypt(plaintext, key):
    """Decrypt the ciphertext using AES-CTR mode with the given key and nonce."""
    nonce = urandom(8) # Get 8 random bytes
    cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
    return nonce + cipher.encrypt(plaintext)

# === AES Decryption (AES-256-CTR) ===
def aes_ctr_decrypt(ciphertext, key):
    """Decrypt the ciphertext using AES-CTR mode with the given key and nonce."""
    nonce = ciphertext[:8]
    ciphertext = ciphertext[8:]
    cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
    return cipher.decrypt(ciphertext)

msg = "Hello World"
passwd = getpass("Enter Encryption Password: ")
salt = urandom(16) # Get 16 random bytes

# Derive encryption key
derived_key = derive_hmac_key(passwd, 
                              salt, 
                              iterations=1000000, 
                              dklen=32)

# Calculate HMAC_SHA512
hmac_s512 = calc_hmac(derived_key, msg.encode())

# Encrypt msg with derived_key
ciphertext = hmac_s512 + salt + aes_ctr_encrypt(msg.encode(), derived_key)
print(f"Ciphertext: {ciphertext.hex()}")

# Extract decryption params
passwd = getpass("Enter Decryption Password: ")
hmac_s512_hex = ciphertext[:64]
salt = ciphertext[64:80]
dervied_key = derive_hmac_key(passwd, 
                              salt, 
                              iterations=1000000, 
                              dklen=32)
ciphertext = ciphertext[80:]

# Decrypt the ciphertext and verify the HMAC_SHA512
plaintext = aes_ctr_decrypt(ciphertext, derived_key)
if calc_hmac(derived_key, plaintext) == hmac_s512_hex:
    print("[+] HMAC Verified")
    print(f"Plaintext: {plaintext.decode()}")
else:
    print("[X] HMAC Failed!")


# Output:
python3 encipherit-improved.py
Enter Encryption Password:
Ciphertext: e6fd7a0bfe68abe01143facebb8992ec6e08c6cd4bf17c593ff6f24eed487559cf654a017a19660dd6b4d53805336523c091751aa32eb6ab9836ad32fa7a0ce066736e2f5c45f5425f7eac66b13968b54f0ffbca691983d4bd546c6a28b1878f0eb339
Enter Decryption Password:
[+] HMAC Verified
Plaintext: Hello World
```

## Closing Thoughts
This research project into the **EncipherIt** encryption tool revealed several serious cryptographic weaknesses that compromise its overall security. By reverse-engineering the key derivation function and analysing how the encryption was applied, I was able to break down its security model and identify critical flaws in how it operates.

The use of **PBKDF2 with only 1000 iterations** makes key derivation far too weak by modern cryptographic standards, leaving it vulnerable to brute-force attacks. The decision to use **AES-ECB** as an intermediate step, with the derived key acting as both data and key, introduces several issues that effectively reduces its security. 

The final encryption step, using **AES-CTR**, is undermined by the flawed key transformation process and a critical design oversight: the **nonce is derived from the Unix timestamp**, making it possible to infer when an encryption event occurred and significantly narrowing the search space for potential attacks and correlating encryption time to real-world events.

By carefully stepping through each stage of the encryption, I was able to demonstrate how an attacker could reverse the process and recover meaningful data, proving that this implementation does not provide the level of security it claims. This highlights a broader issue in the world of browser-based encryption tools—many offer a false sense of security while quietly implementing **poor cryptographic practices** behind the scenes.

The key takeaway? Cryptography is **unforgiving** when implemented incorrectly. Even small design flaws can lead to complete breakdowns in security. If nothing else, this project reinforced the importance of **never trusting proprietary encryption without verification** and always scrutinizing how an encryption system derives and handles its keys.

I enjoyed researching and building this tool, and I hope you found my research both informative and entertaining. If you have any insights, questions, criticisms or want to discuss cryptography, feel free to reach out!

-DW
