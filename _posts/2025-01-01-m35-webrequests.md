---
layout: post
title: HTB Academy - Web Requests Module
author: Dave Winton
category: cybersecurity 
feature-img: "assets/img/pexels/Network.jpg"
tags: [hackthebox]
excerpt_separator: <!--more-->
---

This module introduces the topic of HTTP web requests and how different web applications utilize them to communicate with their backends.
<!--more-->

## Module Contents
- [Module Contents](#module-contents)
- [Section 01 - HyperText Transfer Protocol (HTTP)](#section-01---hypertext-transfer-protocol-http)
- [Section 02 - Hypertext Transfer Protocol Secure (HTTPS)](#section-02---hypertext-transfer-protocol-secure-https)
- [Section 03 - HTTP Requests and Responses](#section-03---http-requests-and-responses)
- [Section 04 - HTTP Headers](#section-04---http-headers)
- [Section 05 - HTTP Methods and Codes](#section-05---http-methods-and-codes)
- [Section 06 - GET](#section-06---get)
- [Section 07 - POST](#section-07---post)
- [Section 08 - CRUD API](#section-08---crud-api)


## Section 01 - HyperText Transfer Protocol (HTTP)

HTTP (Hypertext Transfer Protocol) is the foundation of web communication, enabling clients (browsers, scripts) to send requests and receive responses from servers. It operates over port 80 by default (443 for HTTPS) and facilitates interactions through URLs (Uniform Resource Locators). A URL consists of a scheme (protocol), host (domain or IP), port, path (resource location), query strings (parameters), and fragments (client-side anchors). When a URL is entered, the browser performs a DNS lookup to resolve the domain to an IP, then sends an HTTP request (e.g., GET) to the server, which processes it and returns a response, often an HTML page with a status code like 200 OK.

For testing and automation, cURL is a command-line tool that allows sending web requests directly. A basic request is made using curl example.com, while -O saves the response as a file. Additional flags allow customization, such as -i to include headers, -u user:pass for authentication, and -A to spoof the user agent. cURL is essential for penetration testing, automation, and debugging, offering a more granular way to inspect web traffic compared to a browser.

**Solutions:**

1. To get the flag, start the above exercise, then use cURL to download the file returned by '/download.php' in the server shown above.

To do this we can use the most basic `curl` command and just append `/download.php` to the url.

```shell
curl 94.237.52.110:49021/download.php
HTB{64$!c_cURL_u$3r}
```

Answer: `HTB{64$!c_cURL_u$3r}`

## Section 02 - Hypertext Transfer Protocol Secure (HTTPS)

HTTP transmits data in plain text, making it vulnerable to interception through Man-in-the-Middle (MITM) attacks. HTTPS (Hypertext Transfer Protocol Secure) was introduced to address this issue by encrypting communications between the client and server, ensuring data confidentiality and integrity. Even if intercepted, encrypted traffic cannot be easily deciphered. HTTPS relies on Transport Layer Security (TLS) to establish a secure connection via a handshake process, which involves exchanging certificates and cryptographic keys. Once the handshake is complete, all subsequent HTTP communication is encrypted. HTTPS is now the standard for web security, with browsers phasing out support for plain HTTP.

In practice, HTTPS secures sensitive information such as login credentials, making it inaccessible to attackers on the same network. Browsers indicate HTTPS with a lock icon or "https://" in the URL. However, the security of HTTPS can still be compromised by DNS leaks or downgrade attacks that revert connections to HTTP. To mitigate these risks, users can adopt encrypted DNS servers or VPNs. Tools like cURL automatically handle HTTPS standards but may reject invalid or outdated SSL certificates, warning users against potential MITM attacks. For local or practice environments, the `-k` flag in cURL bypasses certificate checks when necessary.

## Section 03 - HTTP Requests and Responses

HTTP communication follows a request-response model where a client (such as a web browser or cURL) sends an HTTP request to a server, which processes it and returns an HTTP response. A request contains essential information like the HTTP method (e.g., `GET`, `POST`), the requested resource path, and headers specifying parameters or additional data. The server's response includes a status code indicating the outcome, headers describing metadata, and often a response body containing HTML, JSON, or other content types. Modern HTTP versions, such as HTTP/2, improve efficiency by using binary data instead of plain text.

Tools like cURL provide detailed insights into HTTP requests and responses, which is useful for debugging or penetration testing. Using the `-v` flag in cURL reveals the full request and response details, while web browsers offer built-in developer tools (DevTools) that allow users to inspect network activity, analyze headers, and track resource requests. These tools help developers and security professionals monitor how web applications interact with servers and diagnose potential vulnerabilities in HTTP communication.

**Solutions:**

1. What is the HTTP method used while intercepting the request? (case-sensitive)

Answer: `GET`

2. Send a GET request to the above server, and read the response headers to find the version of Apache running on the server, then submit it as the answer. (answer format: X.Y.ZZ)

```shell
curl -X GET 94.237.52.110:49021 -v

Note: Unnecessary use of -X or --request, GET is already inferred.
*   Trying 94.237.52.110:49021...
* Connected to 94.237.52.110 (94.237.52.110) port 49021 (#0)
> GET / HTTP/1.1
> Host: 94.237.52.110:49021
> User-Agent: curl/7.88.1
> Accept: */*
> 
< HTTP/1.1 200 OK
< Date: Mon, 27 Jan 2025 01:46:34 GMT
< Server: Apache/2.4.41 (Ubuntu)
< Vary: Accept-Encoding
< Content-Length: 348
< Content-Type: text/html; charset=UTF-8
< 
<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Blank Page</title>
</head>

<body>
    This page is intentionally left blank.
    <br>
    Using cURL should be enough.
</body>

* Connection #0 to host 94.237.52.110 left intact
</html>
```

Answer: `2.4.41`

## Section 04 - HTTP Headers

HTTP headers facilitate communication between the client and server by passing metadata with requests and responses. They can be categorized into five types:

- General Headers – Used in both requests and responses, describing the message rather than its contents (e.g., Date, Connection).
- Entity Headers – Describe the content being transferred (e.g., Content-Type, Content-Length, Content-Encoding).
- Request Headers – Sent by the client to provide context (e.g., Host, User-Agent, Referer, Authorization, Cookie).
- Response Headers – Sent by the server with additional information (e.g., Server, Set-Cookie, WWW-Authenticate).
- Security Headers – Enhance security by enforcing policies (e.g., Content-Security-Policy, Strict-Transport-Security, Referrer-Policy).

Viewing and Modifying Headers

- cURL: Use `-I` for response headers, `-i` for headers + body, and `-H` to set headers manually.
- Browser DevTools: Inspect headers in the Network tab, with options to view raw headers or structured details.

**Solutions:**

1. The server above loads the flag after the page is loaded. Use the Network tab in the browser devtools to see what requests are made by the page, and find the request to the flag.

First we need to navigate to the url at the `http://<SERVER-IP>:<PORT-NUM>` and use the browser devtools to find the next part of the solution. 

![BBH-M1-S4-**Q1**](/assets/img/htb/bbh_solutions_sec1_page4_q1.png)

Next use curl to get the flag..

```shell
curl http://94.237.54.116:48372/flag_327a6c4304ad5938eaf0efb6cc3e53dc.txt
HTB{p493_r3qu3$t$_m0n!t0r}
```

Answer: `HTB{p493_r3qu3$t$_m0n!t0r}`

## Section 05 - HTTP Methods and Codes

HTTP Methods: These methods define how a client can interact with a server to access or modify resources.

- GET: Requests a resource, can pass data via query strings.
- POST: Sends data to the server, often used for forms or file uploads.
- HEAD: Requests headers without the body, useful for checking resource details before downloading.
- PUT: Creates or replaces a resource on the server.
- DELETE: Deletes a resource from the server.
- OPTIONS: Retrieves information about the server’s supported methods.
- PATCH: Applies partial modifications to a resource.

HTTP Response Codes: Indicate the outcome of a request.

- 1xx: Informational, does not affect processing.
- 2xx: Success (e.g., 200 OK).
- 3xx: Redirection (e.g., 302 Found).
- 4xx: Client error (e.g., 404 Not Found, 400 Bad Request).
- 5xx: Server error (e.g., 500 Internal Server Error).

Most modern web applications use GET and POST, while REST APIs commonly use PUT and DELETE for updating and deleting resources.

## Section 06 - GET

Summary of `GET` requests:

**Browser Requests:** When visiting a URL, browsers default to a GET request to retrieve resources. Additional requests may be sent for other resources, observable through the browser's Network tab in devtools.

**Basic HTTP Authentication:** Some websites require authentication via HTTP Basic Authentication. This method directly prompts users for a username and password without involving the web application's login form. Credentials can be provided through the browser or via cURL using the -u flag or username:password@URL format.

**cURL Authentication:** Using the `-i` flag with cURL allows viewing response headers, showing an "Authorization Required" status for unauthenticated requests. Once authenticated via the Authorization header (Base64 encoded), access is granted, and the response body is returned.

**Authorization Header:** The Authorization header is sent with the credentials, typically in Base64 format. This is shown in the Authorization: Basic YWRtaW46YWRtaW4= header for admin:admin. Using cURL, we can manually set the Authorization header with -H.

**GET Parameters:** After authentication, you can interact with the website’s functionality (e.g., a city search feature). The search terms are sent via GET parameters, observable in the Network tab. These can be directly tested with cURL, as shown by sending a GET request with the appropriate search parameter (e.g., search=le).

**cURL and Fetch:** You can easily obtain the cURL command or Fetch API request from the Network tab to replicate requests and examine the responses.

**Solutions:**

1. The exercise above seems to be broken, as it returns incorrect results. Use the browser devtools to see what is the request it is sending when we search, and use cURL to search for 'flag' and obtain the flag.

**Hint:** *Don't forget to set the user credentials when you send the 'search' request*

To solve this exercise, we use the browser devtools to inspect the request sent when searching for a term. By monitoring the Network tab, we can observe the `GET` request structure, including the URL and query parameters. By manipulating the search parameter we can get the flag with a simple curl command..

```shell
curl 'http://admin:admin@94.237.54.116:37303/search.php?search=flag'
flag: HTB{curl_g3773r}
```

Answer: `HTB{curl_g3773r}`

## Section 07 - POST

HTTP POST requests are used by web applications to send data securely within the request body, rather than in the URL, as is the case with GET requests. This method is beneficial for transferring larger amounts of data, handling file uploads, and preventing the logging of sensitive data. It also avoids the need for URL encoding, as POST can accept binary data directly. Additionally, POST requests can handle larger payloads, which is important when the data exceeds URL length limits imposed by browsers and web servers.

In web applications, POST requests are commonly used for login forms, where user credentials are sent to the server. Once authenticated, the server responds with a session cookie to maintain the user's logged-in state. This allows users to interact with the web app without needing to re-enter credentials. Furthermore, POST requests can carry JSON data, and it's important to set the correct Content-Type header for proper interaction. Tools like cURL and browser devtools help replicate and automate these requests, which is particularly useful for security assessments and bug bounty exercises.

**Solutions:**

1. Obtain a session cookie through a valid login, and then use the cookie with cURL to search for the flag through a JSON POST request to '/search.php'

**Hint:** *You may login through a browser and collect the cookie from the Storage tab. You may also use the '-i' or '-v' flags with cURL to view the response header and get the cookie.*

Let's break down the problem in 2 parts:
- Obtain a value session cookie through login with `admin:admin`
- Search for the flag by sending a `POST` to the `/search.php` url with the session cookie.

We can do this in the browser as the question suggests, but it's also easy (and good practice!) to do this with `curl`.

First let's obtain the cookie:

```shell
curl -X POST \
-d 'username=admin&password=admin' \
'http://94.237.52.110:37335/' -i

HTTP/1.1 200 OK
Date: Mon, 27 Jan 2025 02:29:18 GMT
Server: Apache/2.4.41 (Ubuntu)
Set-Cookie: PHPSESSID=p3474j0bm7161uh30ki9nuqb2g; path=/
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Vary: Accept-Encoding
Content-Length: 1554
Content-Type: text/html; charset=UTF-8
--- SNIP ---
```

Next we pass that cookie along with the other necessary parameters to the `/search.php` url..

```shell
curl -X POST -d '{"search":"flag"}' \ 
-b 'PHPSESSID=p3474j0bm7161uh30ki9nuqb2g' \
-H 'Content-Type: application/json' http://94.237.52.110:37335/search.php

["flag: HTB{p0$t_r3p34t3r}"]
```

Answer: `HTB{p0$t_r3p34t3r`

## Section 08 - CRUD API

CRUD refers to the four basic operations used to interact with a database: Create, Read, Update, and Delete. These operations are mapped to HTTP methods as follows:

- Create (POST): Adds new data to a database. This is done by sending a POST request with the data to be added.
- Read (GET): Retrieves data from the database. A GET request is used to read the data, often returning results in JSON format.
- Update (PUT): Modifies existing data in the database. A PUT request is used to update an entity, typically replacing the entire entry.
- Delete (DELETE): Removes data from the database. A DELETE request is sent to remove the specified entity from the database.

These operations are commonly used in APIs for interacting with database records, and access to them is usually controlled through authentication mechanisms.

**Solutions:**

1. First, try to update any city's name to be 'flag'. Then, delete any city. Once done, search for a city named 'flag' to get the flag.

**Hint:** *Make sure that the number of cities is less than when you started. If you added any new cities, you should deleted them as well.*

First we need to identify city names. We can do this by using a `curl` request then piping the output into `jq` 

```shell
curl -s http://94.237.54.42:49553/api.php/city/ | jq
[
  {
    "city_name": "London",
    "country_name": "(UK)"
  },
  {
    "city_name": "Birmingham",
    "country_name": "(UK)"
  },
  {
    "city_name": "Leeds",
    "country_name": "(UK)"
  },
  {
    "city_name": "Glasgow",
    "country_name": "(UK)"
  },
--- SNIP ---
```

Next we can change a city name (`London` for example) to `flag` using an UPDATE method..

```shell
curl -X PUT http://94.237.54.42:49553/api.php/city/london -d '{"city_name":"flag", "country_name":"flagland"}' -H 'Content-Type: application/json'
```

Then we delete any city as the question intructed us to do. Let's use `Leeds` for example..

```shell
curl -X DELETE http://94.237.54.42:49553/api.php/city/Leeds
```

Finally we search for the city now named `flag`..

```shell
curl http://94.237.54.42:49553/api.php/city/flag
[{"city_name":"flag","country_name":"HTB{crud_4p!_m4n!pul4t0r}"}]┌
```

Answer: `HTB{crud_4p!_m4n!pul4t0r}`