# OWASP ZAP Scan Report

**Target:** `https://localhost:8443/benchmark/Index.html`  
**Scan date:** 2026-05-05_02-35-23  
**ZAP exit code:** 0

## Summary

| Risk | Count |
|------|------:|
| 🔴 HIGH | 5 |
| 🟡 MEDIUM | 17 |
| 🔵 LOW | 61 |
| ⚪ INFORMATIONAL | 45 |
| **TOTAL** | **128** |

## Findings

### 🔴 PII Disclosure
- **Risk:** HIGH  
- **CWE:** 359  
- **Instances:** 5  
- **Description:** <p>The response contains Personally Identifiable Information, such as CC number, SSN and similar sensitive data.</p>  
- **Solution:** <p>Check the response for the potential presence of personally identifiable information (PII), ensure nothing sensitive is leaked by the application.</p>  

**Affected URLs (up to 5):**

- `POST https://localhost:8443/benchmark/weakrand-01/BenchmarkTest00489`
- `POST https://localhost:8443/benchmark/weakrand-03/BenchmarkTest01448`
- `POST https://localhost:8443/benchmark/weakrand-03/BenchmarkTest01575`
- `POST https://localhost:8443/benchmark/weakrand-04/BenchmarkTest02004`
- `POST https://localhost:8443/benchmark/weakrand-05/BenchmarkTest02255`

### 🟡 Absence of Anti-CSRF Tokens
- **Risk:** MEDIUM  
- **CWE:** 352  
- **Instances:** 5  
- **Description:** <p>No Anti-CSRF tokens were found in a HTML submission form.</p><p>A cross-site request forgery is an attack that involves forcing a victim to send an HTTP request to a target destination without their knowledge or intent in order to perform an action as the victim. The underlying cause is applicati  
- **Solution:** <p>Phase: Architecture and Design</p><p>Use a vetted library or framework that does not allow this weakness to occur or provides constructs that make this weakness easier to avoid.</p><p>For example, use anti-CSRF packages such as the OWASP CSRFGuard.</p><p></p><p>Phase: Implementation</p><p>Ensure  

**Affected URLs (up to 5):**

- `GET https://localhost:8443/benchmark/cmdi-00/BenchmarkTest00015.html?BenchmarkTest00015=SafeText`
- `GET https://localhost:8443/benchmark/ldapi-00/BenchmarkTest00012.html?BenchmarkTest00012=SafeText`
- `GET https://localhost:8443/benchmark/ldapi-00/BenchmarkTest00044.html?BenchmarkTest00044=SafeText`
- `GET https://localhost:8443/benchmark/securecookie-00/BenchmarkTest00016.html?BenchmarkTest00016=SafeText`
- `GET https://localhost:8443/benchmark/securecookie-00/BenchmarkTest00170.html?BenchmarkTest00170=SafeText`

### 🟡 CSP: script-src unsafe-inline
- **Risk:** MEDIUM  
- **CWE:** 693  
- **Instances:** 5  
- **Description:** <p>Content Security Policy (CSP) is an added layer of security that helps to detect and mitigate certain types of attacks. Including (but not limited to) Cross Site Scripting (XSS), and data injection attacks. These attacks are used for everything from data theft to site defacement or distribution o  
- **Solution:** <p>Ensure that your web server, application server, load balancer, etc. is properly configured to set the Content-Security-Policy header.</p>  

**Affected URLs (up to 5):**

- `GET https://localhost:8443/benchmark/` (`Content-Security-Policy`)
- `GET https://localhost:8443/benchmark/Index.html` (`Content-Security-Policy`)
- `GET https://localhost:8443/benchmark/ldapi-00/BenchmarkTest00012.html?BenchmarkTest00012=SafeText` (`Content-Security-Policy`)
- `GET https://localhost:8443/benchmark/ldapi-Index.html` (`Content-Security-Policy`)
- `GET https://localhost:8443/benchmark/securecookie-Index.html` (`Content-Security-Policy`)

### 🟡 Content Security Policy (CSP) Header Not Set
- **Risk:** MEDIUM  
- **CWE:** 693  
- **Instances:** 2  
- **Description:** <p>Content Security Policy (CSP) is an added layer of security that helps to detect and mitigate certain types of attacks, including Cross Site Scripting (XSS) and data injection attacks. These attacks are used for everything from data theft to site defacement or distribution of malware. CSP provide  
- **Solution:** <p>Ensure that your web server, application server, load balancer, etc. is configured to set the Content-Security-Policy header.</p>  

**Affected URLs (up to 5):**

- `GET https://localhost:8443/`
- `GET https://localhost:8443/robots.txt`

### 🟡 Sub Resource Integrity Attribute Missing
- **Risk:** MEDIUM  
- **CWE:** 345  
- **Instances:** 5  
- **Description:** <p>The integrity attribute is missing on a script or link tag served by an external server. The integrity tag prevents an attacker who have gained access to this server from injecting a malicious content.</p>  
- **Solution:** <p>Provide a valid integrity attribute to the tag.</p>  

**Affected URLs (up to 5):**

- `GET https://localhost:8443/benchmark/`
- `GET https://localhost:8443/benchmark/Index.html`
- `GET https://localhost:8443/benchmark/ldapi-Index.html`
- `GET https://localhost:8443/benchmark/securecookie-Index.html`
- `GET https://localhost:8443/benchmark/xpathi-Index.html`

### 🔵 Application Error Disclosure
- **Risk:** LOW  
- **CWE:** 550  
- **Instances:** 11  
- **Description:** <p>This page contains an error/warning message that may disclose sensitive information like the location of the file that produced the unhandled exception. This information can be used to launch further attacks against the web application. The alert could be a false positive if the error message is  
- **Solution:** <p>Review the source code of this page. Implement custom error pages. Consider implementing a mechanism to provide a unique error reference/identifier to the client (browser) while logging the details on the server side and not exposing them to the user.</p>  

**Affected URLs (up to 5):**

- `GET https://localhost:8443/benchmark/`
- `GET https://localhost:8443/benchmark/Index.html`
- `GET https://localhost:8443/benchmark/cmdi-00/BenchmarkTest00007.html?BenchmarkTest00007=SafeText`
- `GET https://localhost:8443/benchmark/cmdi-00/BenchmarkTest00015.html?BenchmarkTest00015=SafeText`
- `GET https://localhost:8443/benchmark/css/normalize.css`
- _…and 6 more_

### 🔵 Cookie Without Secure Flag
- **Risk:** LOW  
- **CWE:** 614  
- **Instances:** 5  
- **Description:** <p>A cookie has been set without the secure flag, which means that the cookie can be accessed via unencrypted connections.</p>  
- **Solution:** <p>Whenever a cookie contains sensitive information or is a session token, then it should always be passed using an encrypted channel. Ensure that the secure flag is set for cookies containing such sensitive information.</p>  

**Affected URLs (up to 5):**

- `POST https://localhost:8443/benchmark/securecookie-00/BenchmarkTest00087` (`SomeCookie`)
- `POST https://localhost:8443/benchmark/securecookie-00/BenchmarkTest00348` (`SomeCookie`)
- `POST https://localhost:8443/benchmark/securecookie-00/BenchmarkTest00403` (`SomeCookie`)
- `POST https://localhost:8443/benchmark/securecookie-00/BenchmarkTest00491` (`SomeCookie`)
- `POST https://localhost:8443/benchmark/securecookie-00/BenchmarkTest00736` (`SomeCookie`)

### 🔵 Cross-Origin-Embedder-Policy Header Missing or Invalid
- **Risk:** LOW  
- **CWE:** 693  
- **Instances:** 5  
- **Description:** <p>Cross-Origin-Embedder-Policy header is a response header that prevents a document from loading any cross-origin resources that don't explicitly grant the document permission (using CORP or CORS).</p>  
- **Solution:** <p>Ensure that the application/web server sets the Cross-Origin-Embedder-Policy header appropriately, and that it sets the Cross-Origin-Embedder-Policy header to 'require-corp' for documents.</p><p>If possible, ensure that the end user uses a standards-compliant and modern web browser that supports  

**Affected URLs (up to 5):**

- `GET https://localhost:8443/benchmark/cmdi-Index.html` (`Cross-Origin-Embedder-Policy`)
- `GET https://localhost:8443/benchmark/crypto-Index.html` (`Cross-Origin-Embedder-Policy`)
- `GET https://localhost:8443/benchmark/hash-Index.html` (`Cross-Origin-Embedder-Policy`)
- `GET https://localhost:8443/benchmark/pathtraver-Index.html` (`Cross-Origin-Embedder-Policy`)
- `GET https://localhost:8443/benchmark/trustbound-Index.html` (`Cross-Origin-Embedder-Policy`)

### 🔵 Cross-Origin-Opener-Policy Header Missing or Invalid
- **Risk:** LOW  
- **CWE:** 693  
- **Instances:** 5  
- **Description:** <p>Cross-Origin-Opener-Policy header is a response header that allows a site to control if others included documents share the same browsing context. Sharing the same browsing context with untrusted documents might lead to data leak.</p>  
- **Solution:** <p>Ensure that the application/web server sets the Cross-Origin-Opener-Policy header appropriately, and that it sets the Cross-Origin-Opener-Policy header to 'same-origin' for documents.</p><p>'same-origin-allow-popups' is considered as less secured and should be avoided.</p><p>If possible, ensure t  

**Affected URLs (up to 5):**

- `GET https://localhost:8443/benchmark/cmdi-Index.html` (`Cross-Origin-Opener-Policy`)
- `GET https://localhost:8443/benchmark/crypto-Index.html` (`Cross-Origin-Opener-Policy`)
- `GET https://localhost:8443/benchmark/hash-Index.html` (`Cross-Origin-Opener-Policy`)
- `GET https://localhost:8443/benchmark/pathtraver-Index.html` (`Cross-Origin-Opener-Policy`)
- `GET https://localhost:8443/benchmark/trustbound-Index.html` (`Cross-Origin-Opener-Policy`)

### 🔵 Cross-Origin-Resource-Policy Header Missing or Invalid
- **Risk:** LOW  
- **CWE:** 693  
- **Instances:** 5  
- **Description:** <p>Cross-Origin-Resource-Policy header is an opt-in header designed to counter side-channels attacks like Spectre. Resource should be specifically set as shareable amongst different origins.</p>  
- **Solution:** <p>Ensure that the application/web server sets the Cross-Origin-Resource-Policy header appropriately, and that it sets the Cross-Origin-Resource-Policy header to 'same-origin' for all web pages.</p><p>'same-site' is considered as less secured and should be avoided.</p><p>If resources must be shared,  

**Affected URLs (up to 5):**

- `GET https://localhost:8443/benchmark/cmdi-Index.html` (`Cross-Origin-Resource-Policy`)
- `GET https://localhost:8443/benchmark/crypto-Index.html` (`Cross-Origin-Resource-Policy`)
- `GET https://localhost:8443/benchmark/hash-Index.html` (`Cross-Origin-Resource-Policy`)
- `GET https://localhost:8443/benchmark/pathtraver-Index.html` (`Cross-Origin-Resource-Policy`)
- `GET https://localhost:8443/benchmark/trustbound-Index.html` (`Cross-Origin-Resource-Policy`)

### 🔵 In Page Banner Information Leak
- **Risk:** LOW  
- **CWE:** 497  
- **Instances:** 5  
- **Description:** <p>The server returned a version banner string in the response content. Such information leaks may allow attackers to further target specific issues impacting the product and version in use.</p>  
- **Solution:** <p>Configure the server to prevent such information leaks. For example:</p><p>Under Tomcat this is done via the "server" directive and implementation of custom error pages.</p><p>Under Apache this is done via the "ServerSignature" and "ServerTokens" directives.</p>  

**Affected URLs (up to 5):**

- `GET https://localhost:8443/`
- `GET https://localhost:8443/robots.txt`
- `GET https://localhost:8443/sitemap.xml`
- `POST https://localhost:8443/benchmark/ldapi-00/BenchmarkTest00044`
- `POST https://localhost:8443/benchmark/securecookie-00/BenchmarkTest00169`

### 🔵 Information Disclosure - Debug Error Messages
- **Risk:** LOW  
- **CWE:** 1295  
- **Instances:** 12  
- **Description:** <p>The response appeared to contain common error messages returned by platforms such as ASP.NET, and Web-servers such as IIS and Apache. You can configure the list of common debug messages.</p>  
- **Solution:** <p>Disable debugging messages before pushing to production.</p>  

**Affected URLs (up to 5):**

- `GET https://localhost:8443/benchmark/ldapi-00/BenchmarkTest00021?BenchmarkTest00021=Ms+Bar&password=ZAP&username=ZAP`
- `GET https://localhost:8443/benchmark/ldapi-00/BenchmarkTest00367?BenchmarkTest00367=Ms+Bar&password=ZAP&username=ZAP`
- `POST https://localhost:8443/benchmark/cmdi-00/BenchmarkTest00017`
- `POST https://localhost:8443/benchmark/ldapi-00/BenchmarkTest00012`
- `POST https://localhost:8443/benchmark/ldapi-00/BenchmarkTest00044`
- _…and 7 more_

### 🔵 Permissions Policy Header Not Set
- **Risk:** LOW  
- **CWE:** 693  
- **Instances:** 5  
- **Description:** <p>Permissions Policy Header is an added layer of security that helps to restrict from unauthorized access or usage of browser/client features by web resources. This policy ensures the user privacy by limiting or specifying the features of the browsers can be used by the web resources. Permissions P  
- **Solution:** <p>Ensure that your web server, application server, load balancer, etc. is configured to set the Permissions-Policy header.</p>  

**Affected URLs (up to 5):**

- `GET https://localhost:8443/benchmark/cmdi-Index.html`
- `GET https://localhost:8443/benchmark/crypto-Index.html`
- `GET https://localhost:8443/benchmark/ldapi-00/BenchmarkTest00044.html?BenchmarkTest00044=SafeText`
- `GET https://localhost:8443/benchmark/securecookie-00/BenchmarkTest00170.html?BenchmarkTest00170=SafeText`
- `GET https://localhost:8443/benchmark/trustbound-Index.html`

### 🔵 Strict-Transport-Security Header Not Set
- **Risk:** LOW  
- **CWE:** 319  
- **Instances:** 3  
- **Description:** <p>HTTP Strict Transport Security (HSTS) is a web security policy mechanism whereby a web server declares that complying user agents (such as a web browser) are to interact with it using only secure HTTPS connections (i.e. HTTP layered over TLS/SSL). HSTS is an IETF standards track protocol and is s  
- **Solution:** <p>Ensure that your web server, application server, load balancer, etc. is configured to enforce Strict-Transport-Security.</p>  

**Affected URLs (up to 5):**

- `GET https://localhost:8443/`
- `GET https://localhost:8443/robots.txt`
- `GET https://localhost:8443/sitemap.xml`

### 🔵 Timestamp Disclosure - Unix
- **Risk:** LOW  
- **CWE:** 497  
- **Instances:** 5  
- **Description:** <p>A timestamp was disclosed by the application/web server. - Unix</p>  
- **Solution:** <p>Manually confirm that the timestamp data is not sensitive, and that the data cannot be aggregated to disclose exploitable patterns.</p>  

**Affected URLs (up to 5):**

- `POST https://localhost:8443/benchmark/weakrand-00/BenchmarkTest00042`
- `POST https://localhost:8443/benchmark/weakrand-00/BenchmarkTest00042` (`Set-Cookie`)
- `POST https://localhost:8443/benchmark/weakrand-00/BenchmarkTest00164`
- `POST https://localhost:8443/benchmark/weakrand-00/BenchmarkTest00164` (`Set-Cookie`)
- `POST https://localhost:8443/benchmark/weakrand-00/BenchmarkTest00235` (`Set-Cookie`)

### ⚪ Authentication Request Identified
- **Risk:** INFORMATIONAL  
- **CWE:** -1  
- **Instances:** 12  
- **Description:** <p>The given request has been identified as an authentication request. The 'Other Info' field contains a set of key=value lines which identify any relevant fields. If the request is in a context which has an Authentication Method set to "Auto-Detect" then this rule will change the authentication to  
- **Solution:** <p>This is an informational alert rather than a vulnerability and so there is nothing to fix.</p>  

**Affected URLs (up to 5):**

- `GET https://localhost:8443/benchmark/hash-00/BenchmarkTest00046?BenchmarkTest00046=someSecret&password=ZAP&username=ZAP` (`username`)
- `GET https://localhost:8443/benchmark/ldapi-00/BenchmarkTest00021?BenchmarkTest00021=Ms+Bar&password=ZAP&username=ZAP` (`username`)
- `GET https://localhost:8443/benchmark/ldapi-00/BenchmarkTest00367?BenchmarkTest00367=Ms+Bar&password=ZAP&username=ZAP` (`username`)
- `GET https://localhost:8443/benchmark/ldapi-00/BenchmarkTest00694?BenchmarkTest00694=Ms+Bar&password=ZAP&username=ZAP` (`username`)
- `GET https://localhost:8443/benchmark/trustbound-00/BenchmarkTest00031?BenchmarkTest00031=my_user_id&password=ZAP&username=ZAP` (`username`)
- _…and 7 more_

### ⚪ Cookie Poisoning
- **Risk:** INFORMATIONAL  
- **CWE:** 565  
- **Instances:** 5  
- **Description:** <p>This check looks at user-supplied input in query string parameters and POST data to identify where cookie parameters might be controlled. This is called a cookie poisoning attack, and becomes exploitable when an attacker can manipulate the cookie in various ways. In some cases this will not be ex  
- **Solution:** <p>Do not allow user input to control cookie names and values. If some query string parameters must be set in cookie values, be sure to filter out semicolon's that can serve as name/value pair delimiters.</p>  

**Affected URLs (up to 5):**

- `POST https://localhost:8443/benchmark/securecookie-00/BenchmarkTest00348` (`BenchmarkTest00348`)
- `POST https://localhost:8443/benchmark/securecookie-00/BenchmarkTest00403` (`BenchmarkTest00403`)
- `POST https://localhost:8443/benchmark/securecookie-00/BenchmarkTest00404` (`BenchmarkTest00404`)
- `POST https://localhost:8443/benchmark/securecookie-00/BenchmarkTest00405` (`BenchmarkTest00405`)
- `POST https://localhost:8443/benchmark/securecookie-00/BenchmarkTest00655` (`BenchmarkTest00655`)

### ⚪ Information Disclosure - Sensitive Information in URL
- **Risk:** INFORMATIONAL  
- **CWE:** 598  
- **Instances:** 5  
- **Description:** <p>The request appeared to contain sensitive information leaked in the URL. This can violate PCI and most organizational compliance policies. You can configure the list of strings for this check to add or remove values specific to your environment.</p>  
- **Solution:** <p>Do not pass sensitive information in URIs.</p>  

**Affected URLs (up to 5):**

- `GET https://localhost:8443/benchmark/ldapi-00/BenchmarkTest00021?BenchmarkTest00021=Ms+Bar&password=ZAP&username=ZAP` (`password`)
- `GET https://localhost:8443/benchmark/ldapi-00/BenchmarkTest00021?BenchmarkTest00021=Ms+Bar&password=ZAP&username=ZAP` (`username`)
- `GET https://localhost:8443/benchmark/trustbound-00/BenchmarkTest00031?BenchmarkTest00031=my_user_id&password=ZAP&username=ZAP` (`password`)
- `GET https://localhost:8443/benchmark/trustbound-00/BenchmarkTest00031?BenchmarkTest00031=my_user_id&password=ZAP&username=ZAP` (`username`)
- `GET https://localhost:8443/benchmark/xpathi-00/BenchmarkTest00442?BenchmarkTest00442=2222&password=ZAP&username=ZAP` (`password`)

### ⚪ Information Disclosure - Suspicious Comments
- **Risk:** INFORMATIONAL  
- **CWE:** 615  
- **Instances:** 1  
- **Description:** <p>The response appears to contain suspicious comments which may help an attacker.</p>  
- **Solution:** <p>Remove all comments that return information that may help an attacker and fix any underlying problems they refer to.</p>  

**Affected URLs (up to 5):**

- `GET https://localhost:8443/benchmark/js/testsuiteutils.js`

### ⚪ Modern Web Application
- **Risk:** INFORMATIONAL  
- **CWE:** -1  
- **Instances:** 5  
- **Description:** <p>The application appears to be a modern web application. If you need to explore it automatically then the Ajax Spider may well be more effective than the standard one.</p>  
- **Solution:** <p>This is an informational alert and so no changes are required.</p>  

**Affected URLs (up to 5):**

- `GET https://localhost:8443/benchmark/cmdi-00/BenchmarkTest00015.html?BenchmarkTest00015=SafeText`
- `GET https://localhost:8443/benchmark/ldapi-00/BenchmarkTest00012.html?BenchmarkTest00012=SafeText`
- `GET https://localhost:8443/benchmark/ldapi-00/BenchmarkTest00044.html?BenchmarkTest00044=SafeText`
- `GET https://localhost:8443/benchmark/securecookie-00/BenchmarkTest00016.html?BenchmarkTest00016=SafeText`
- `GET https://localhost:8443/benchmark/securecookie-00/BenchmarkTest00170.html?BenchmarkTest00170=SafeText`

### ⚪ Non-Storable Content
- **Risk:** INFORMATIONAL  
- **CWE:** 524  
- **Instances:** 5  
- **Description:** <p>The response contents are not storable by caching components such as proxy servers. If the response does not contain sensitive, personal or user-specific information, it may benefit from being stored and cached, to improve performance.</p>  
- **Solution:** <p>The content may be marked as storable by ensuring that the following conditions are satisfied:</p><p>The request method must be understood by the cache and defined as being cacheable ("GET", "HEAD", and "POST" are currently defined as cacheable)</p><p>The response status code must be understood b  

**Affected URLs (up to 5):**

- `GET https://localhost:8443/benchmark/cmdi-Index.html`
- `GET https://localhost:8443/benchmark/crypto-Index.html`
- `GET https://localhost:8443/benchmark/css/normalize.css`
- `GET https://localhost:8443/benchmark/ldapi-00/BenchmarkTest00044.html?BenchmarkTest00044=SafeText`
- `GET https://localhost:8443/benchmark/trustbound-Index.html`

### ⚪ Session Management Response Identified
- **Risk:** INFORMATIONAL  
- **CWE:** -1  
- **Instances:** 12  
- **Description:** <p>The given response has been identified as containing a session management token. The 'Other Info' field contains a set of header tokens that can be used in the Header Based Session Management Method. If the request is in a context which has a Session Management Method set to "Auto-Detect" then th  
- **Solution:** <p>This is an informational alert rather than a vulnerability and so there is nothing to fix.</p>  

**Affected URLs (up to 5):**

- `GET https://localhost:8443/benchmark/cmdi-00/BenchmarkTest00091` (`BenchmarkTest00091`)
- `GET https://localhost:8443/benchmark/cmdi-00/BenchmarkTest00092` (`BenchmarkTest00092`)
- `GET https://localhost:8443/benchmark/crypto-00/BenchmarkTest00053` (`BenchmarkTest00053`)
- `GET https://localhost:8443/benchmark/crypto-00/BenchmarkTest00054` (`BenchmarkTest00054`)
- `GET https://localhost:8443/benchmark/crypto-00/BenchmarkTest00055` (`BenchmarkTest00055`)
- _…and 7 more_


---

_Generated by zap_full_report.py — 2026-05-05_02-35-23_
