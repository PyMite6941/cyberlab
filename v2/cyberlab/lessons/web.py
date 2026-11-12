"""Debriefs for the web track."""

from __future__ import annotations

from cyberlab.lessons import Bullets, Code, Lesson, register

PORTSWIGGER_SQLI = ("PortSwigger Web Security Academy: SQL injection (free interactive labs)",
                    "https://portswigger.net/web-security/sql-injection")
PORTSWIGGER_XSS = ("PortSwigger Web Security Academy: cross-site scripting",
                   "https://portswigger.net/web-security/cross-site-scripting")

register(Lesson(
    id="web-sqli",
    title="SQL injection",
    summary=("You logged in as admin without the password, by typing SQL instead of a "
             "username. The login form did exactly what its code told it to: it handed "
             "your text to the database as part of a command."),
    attacked=[
        "The weak link is one line of the server's code: the line that builds the login "
        "query. Everything before it (the form, the HTTP request) and after it (the "
        "database, the session) worked as designed.",
        Code("""
query = ("SELECT username, role FROM users "
         f"WHERE username = '{username}' AND password = '{password}'")
row = db.execute(query).fetchone()
""", "The vulnerable code in the lab's web app (Python)"),
        "The request travels through a chain: browser form -> HTTP POST body -> the web "
        "app's Python code -> a SQL string -> the database's SQL parser -> a result row -> "
        "'you are logged in'. The attack happens at the fourth link, where your text is "
        "pasted into the SQL string. Specifically it lands in the WHERE clause, the part "
        "of the query that decides which rows match.",
    ],
    how=[
        "A normal login for alice produces a query where the input stays inside the quotes:",
        Code("SELECT username, role FROM users WHERE username = '«alice»' AND password = '«wonderland»'"),
        "With the username  admin' --  the database receives this instead:",
        Code("SELECT username, role FROM users WHERE username = '«admin' --»' AND password = '«x»'"),
        Bullets([
            "The single quote you typed closes the username string early. From that "
            "character on, your input is no longer data: the database reads it as SQL.",
            "The two dashes start a SQL comment, so everything after them, including the "
            "password check, is ignored.",
            "What actually runs is  SELECT username, role FROM users WHERE username = 'admin'. "
            "That matches the admin row, and the app logs you in as whoever the row says.",
        ]),
        "The payload  ' OR 1=1 --  works differently: it makes the WHERE clause true for "
        "every row, and the app takes the first row returned, which happens to be admin. "
        "A lone quote (') leaves the SQL unbalanced, which is why it produced a database "
        "error: that error is how attackers confirm the injection exists.",
        "sqlmap automates the same idea. It sends many variations, watches how the "
        "responses differ, and then asks the database yes/no questions to read out whole "
        "tables, one character at a time:",
        Code("sqlmap -u http://127.0.0.1:<port>/login --data 'username=a&password=b' --batch --dump"),
    ],
    why=[
        "The root cause is mixing code and data. The query is assembled as one string, so "
        "the database has no way to know which characters the developer wrote and which "
        "ones you typed. Any input that contains SQL control characters changes the "
        "meaning of the command.",
        Bullets([
            "No input validation: a username containing a quote and a comment marker was "
            "accepted as-is.",
            "Detailed database errors were shown to the visitor, which tells an attacker "
            "the database type and that the quote reached the SQL parser.",
            "The table stores passwords in plaintext, so once sqlmap dumps it the attacker "
            "has every account, not just admin.",
        ]),
    ],
    defend=[
        "The fix used everywhere today is the parameterized query (also called a prepared "
        "statement). The query's structure and the user's values are sent to the database "
        "separately, so a value can never become part of the command:",
        Code("""
row = db.execute(
    "SELECT username, role FROM users WHERE username = ? AND password = ?",
    (username, password),
).fetchone()
""", "The same lookup, fixed"),
        "With this code the payload  admin' --  is just an odd username that matches no "
        "row. Nothing has to be stripped or escaped by hand, which is why parameterization "
        "is preferred over trying to remove 'bad' characters: a filter has to anticipate "
        "every trick, a parameter does not care what the value contains.",
        "Real applications layer more defenses on top:",
        Bullets([
            "Frameworks and ORMs (Django, SQLAlchemy, Rails, Entity Framework) build "
            "parameterized queries by default.",
            "Input validation with an allow-list: a username may be, say, 3 to 32 letters, "
            "digits, dots or underscores. Reject anything else.",
            "Least privilege for the application's database account, so an injection "
            "cannot read or drop tables the app never needs.",
            "Generic error pages for visitors; the detailed error goes to a server log.",
            "Passwords stored as salted, slow hashes (see the dict-john debrief), so a "
            "dumped table is not a list of working logins.",
            "A web application firewall (WAF) and code scanning in CI as extra layers. "
            "They catch common payloads and risky code, but they are not the fix.",
        ]),
    ],
    detect=[
        "SQL injection attempts stand out in logs because normal usernames do not contain "
        "SQL. The lab's web app logs every login attempt; look at yours:",
        Code("grep 'login attempt' ~/cyberlab/logs/webapp.log"),
        "Indicators to search for in logged input: a single or double quote, the comment "
        "marker --, always-true conditions such as OR 1=1, and SQL keywords (SELECT, "
        "UNION, WHERE, FROM). sqlmap is even easier to spot: hundreds of requests in "
        "seconds from one client, with its own User-Agent unless the attacker changes it.",
    ],
    ced=["5.1.B.2", "5.1.B.3", "5.1.B.4", "5.5.B.1", "5.5.B.2", "5.6.E.1"],
    links=[
        PORTSWIGGER_SQLI,
        ("OWASP SQL Injection Prevention Cheat Sheet",
         "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html"),
        ("OWASP: SQL Injection (attack description and examples)",
         "https://owasp.org/www-community/attacks/SQL_Injection"),
        ("sqlmap usage guide", "https://github.com/sqlmapproject/sqlmap/wiki/Usage"),
    ],
))

register(Lesson(
    id="web-xss",
    title="Reflected cross-site scripting (XSS)",
    summary=("You made the search page run markup you supplied. Nothing on the server was "
             "broken into: the target of XSS is the browser of whoever opens the page."),
    attacked=[
        "The weak link is the line that builds the search results page. It drops the "
        "search term into the HTML without encoding it:",
        Code("""
q = query["q"]
results = f'<h2>Search</h2><p>No products match "{q}".</p>'
""", "The vulnerable code in the lab's web app (Python)"),
        "The chain is: a link or form -> the q parameter in the URL -> the server's page "
        "template -> the HTML sent back -> the browser's HTML parser -> the JavaScript "
        "engine. The server is only a mirror. The part that gets fooled is the browser's "
        "HTML parser, which cannot tell the site's own markup from markup that arrived in "
        "the query string.",
    ],
    how=[
        "Search for  widgets  and the response contains your text as text:",
        Code('<p>No products match "«widgets»".</p>'),
        "Search for a script tag and the response contains your text as markup:",
        Code('<p>No products match "«<script>alert(1)</script>»".</p>'),
        Bullets([
            "The browser parses the response, meets a script element and runs it. It "
            "treats the script as part of the site, because it arrived from the site.",
            "A script running in the site's origin can do what the logged-in user can do "
            "there: read the page, read cookies that are not HttpOnly (try "
            "<script>alert(document.cookie)</script> after logging in), submit forms, or "
            "send what it finds to another server.",
            "It is called reflected because the payload is not stored anywhere. It lives "
            "in a link. The attacker's job is to get a victim to open that link, usually "
            "by phishing, while the victim is logged in.",
            "A script tag is only one way in. An event handler works too, with no script "
            "tag at all:  <img src=x onerror=alert(1)>",
        ]),
    ],
    why=[
        "The page treats user input as trusted HTML. The search term is data, but it is "
        "written into the page in a place where the browser expects code-like markup, and "
        "nothing converts the special characters < > \" ' & into harmless text first.",
        Bullets([
            "No output encoding where the value is inserted into HTML.",
            "The session and role cookies are set without the HttpOnly attribute, so any "
            "script on the page can read them.",
            "No Content-Security-Policy header, so the browser runs inline scripts from "
            "any source.",
        ]),
    ],
    defend=[
        "The primary fix is output encoding: convert the characters that have meaning in "
        "HTML into entities at the moment the value is written into the page.",
        Code("""
import html
results = f'<h2>Search</h2><p>No products match "{html.escape(q)}".</p>'
""", "The same line, fixed"),
        Code('<p>No products match "«&lt;script&gt;alert(1)&lt;/script&gt;»".</p>',
             "What the browser now receives: text that looks like a tag, not a tag"),
        "Modern sites rarely call an escape function by hand. They get the same result "
        "from several layers:",
        Bullets([
            "Template engines and UI frameworks that encode by default (Jinja2 "
            "autoescape, Django templates, React, Angular). XSS today mostly appears "
            "where a developer switches that off, for example with innerHTML or "
            "dangerouslySetInnerHTML.",
            "Content Security Policy: a response header such as  Content-Security-Policy: "
            "script-src 'self'  tells the browser to refuse inline scripts and scripts "
            "from other sites, so an injection that slips through still does not run.",
            "Cookie attributes: HttpOnly hides the session cookie from JavaScript; "
            "Secure and SameSite limit where it is sent.",
            "Input validation as a second check, and a sanitizer library (such as "
            "DOMPurify) for the rare field that must accept some HTML.",
        ]),
        "Encoding depends on context. html.escape is right for text between tags; a "
        "value placed inside a JavaScript string, a URL or a style needs that context's "
        "own encoding.",
    ],
    detect=[
        "Reflected XSS travels in the URL, so it is visible in the web server's access "
        "log. Find your own attempts:",
        Code("grep -i 'script\\|onerror' ~/cyberlab/logs/webapp.log"),
        "The log shows the URL-encoded form (%3Cscript%3E is <script>). Defenders search "
        "request logs for script tags, event handlers such as onerror= and onload=, and "
        "javascript: URLs, in both raw and encoded forms.",
    ],
    ced=["5.1.B.5", "5.1.B.6", "5.5.B.2", "5.6.E.2"],
    links=[
        PORTSWIGGER_XSS,
        ("OWASP Cross Site Scripting Prevention Cheat Sheet",
         "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html"),
        ("MDN: Content Security Policy (CSP)",
         "https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/CSP"),
        ("Google XSS Game (practice levels)", "https://xss-game.appspot.com/"),
    ],
))

register(Lesson(
    id="web-xss-stored",
    title="Stored cross-site scripting (XSS)",
    summary=("You left a comment that runs as code for every later visitor of the "
             "guestbook, and you got it past a filter that was supposed to stop exactly that."),
    attacked=[
        "Two things, in order. First the filter that 'cleans' comments, then the page "
        "that displays them:",
        Code("""
def strip_script_tags(text):
    return re.sub(r"(?i)</?script[^>]*>", "", text)   # remove <script> and </script>

comments.append(strip_script_tags(comment))           # saved
...
page += f"<li>{comment}</li>"                         # shown to every visitor, unencoded
""", "The vulnerable code in the lab's web app (Python)"),
        "The chain is: comment form -> POST body -> the filter -> the stored comment list "
        "-> the guestbook page template -> every visitor's browser. The filter is a "
        "blocklist: it removes one known-bad pattern and lets everything else through.",
    ],
    how=[
        Bullets([
            "A plain <script>alert(1)</script> comment is defused: the filter deletes the "
            "tags and stores  alert(1)  as harmless text.",
            "But a script tag is not the only way to run JavaScript. HTML elements can "
            "carry event handlers, and the filter does not look for those:",
        ]),
        Code("<img src=x onerror=alert(1)>"),
        Bullets([
            "The browser tries to load the image 'x', fails, and runs the onerror "
            "handler. No script tag was ever involved.",
            "Because the comment is saved on the server, the attacker does not need to "
            "send anyone a link. Everyone who opens the guestbook runs the payload, "
            "including staff who are logged in. That is why stored XSS is usually rated "
            "more severe than reflected XSS.",
            "A single-pass filter has another classic flaw. Removing the inner tag from  "
            "<scr<script>ipt>  glues the outer pieces back together into a working "
            "<script> tag.",
        ]),
    ],
    why=[
        "The developer tried to list what is dangerous and remove it. HTML has dozens of "
        "ways to run script (event handlers on almost every element, javascript: links, "
        "SVG, iframes), and new ones appear as browsers evolve, so a blocklist is always "
        "one trick behind.",
        "The real mistake is the same as in reflected XSS: the comment is written into "
        "the page as HTML instead of being encoded as text.",
    ],
    defend=[
        "Encode on output. If comments are plain text, every comment is passed through "
        "the HTML encoder when the page is built, and no payload can become markup:",
        Code('page += f"<li>{html.escape(comment)}</li>"'),
        Bullets([
            "Store what the user typed, encode when displaying. Encoding belongs to the "
            "place the data is used, because the same comment may later be shown in HTML, "
            "in JSON or in an email, each with different rules.",
            "If users are allowed formatting, use an allow-list sanitizer that keeps a "
            "few safe tags and drops everything else (DOMPurify in the browser, bleach or "
            "nh3 in Python), or accept Markdown instead of HTML.",
            "Content Security Policy as the safety net: with  script-src 'self'  and no "
            "'unsafe-inline', inline event handlers such as onerror do not run.",
            "HttpOnly session cookies, so a script that does run cannot steal the session.",
        ]),
    ],
    detect=[
        "Stored XSS arrives in a POST body, which a default access log does not record. "
        "The lab's app logs each new comment so you can see what a defender would look for:",
        Code("grep 'guestbook comment' ~/cyberlab/logs/webapp.log"),
        "Searching only for <script> would miss your winning payload, just like the "
        "filter did. Reviewers also look for event-handler attributes (on...=), "
        "javascript: URLs and unexpected tags in any stored user content.",
    ],
    ced=["5.1.B.5", "5.1.B.6", "5.5.B.2", "5.6.E.2"],
    links=[
        ("PortSwigger Web Security Academy: stored XSS",
         "https://portswigger.net/web-security/cross-site-scripting/stored"),
        ("PortSwigger XSS cheat sheet (every tag and event that can run script)",
         "https://portswigger.net/web-security/cross-site-scripting/cheat-sheet"),
        ("OWASP Cross Site Scripting Prevention Cheat Sheet",
         "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html"),
    ],
))

register(Lesson(
    id="web-cookie",
    title="Trusting a cookie the client controls",
    summary=("You became an admin by editing one cookie. The server asked your browser "
             "what your role was, and believed the answer."),
    attacked=[
        "The weak link is the dashboard's authorization check. At login the server "
        "writes your role into a cookie, and later it reads the role back from that "
        "cookie instead of from its own records:",
        Code("""
# at login
cookies = {"session": "ok", "role": role}
# on /dashboard
role = cookie("role")
if role == "admin": show_admin_dashboard()
""", "The vulnerable logic in the lab's web app"),
        "A cookie is stored by the browser and sent back with every request. The user "
        "owns it and can change it: in the browser's developer tools (Storage tab), with "
        "curl -b, or by editing the request in an intercepting proxy such as Burp Suite.",
    ],
    how=[
        Code("""
Cookie: session=ok; role=«staff»      ->  staff dashboard
Cookie: session=ok; role=«admin»      ->  admin dashboard and the flag
""", "The only difference between the two requests"),
        "No password was guessed and nothing was 'hacked' in the usual sense. This is "
        "privilege escalation through parameter tampering: changing a value the "
        "application assumed you would send back unchanged.",
        "The session cookie has a second problem. Its value is the constant 'ok', so it "
        "proves nothing about who you are; anyone can send it without logging in at all.",
    ],
    why=[
        "The server trusted data from the client. Anything that arrives in a request "
        "(cookies, hidden form fields, headers, JSON) is under the sender's control, no "
        "matter how it got there originally.",
    ],
    defend=[
        Bullets([
            "Server-side sessions: the cookie holds only a long random session ID. The "
            "user's identity and role live on the server, looked up by that ID on every "
            "request. Changing the cookie just logs you out.",
            "If state must live in the cookie (for example a JWT), it is signed with a "
            "key only the server knows, and the server rejects any cookie whose signature "
            "does not verify.",
            "Authorization is checked on the server for every request to a protected "
            "page, against the server's own record of the user.",
            "Cookie attributes: HttpOnly (JavaScript cannot read it), Secure (sent only "
            "over HTTPS), SameSite (not sent on cross-site requests).",
        ]),
        Code("""
session_id = secrets.token_urlsafe(32)          # at login
SESSIONS[session_id] = {"user": name, "role": role}
...
session = SESSIONS.get(cookie("session"))       # on every request
if not session or session["role"] != "admin":
    return forbidden()
""", "The server-side session pattern"),
    ],
    detect=[
        "Tampering shows up as a mismatch: a request that claims a role the account was "
        "never given. Applications log authorization failures and role changes, and "
        "alert when a normal account suddenly reaches admin pages.",
    ],
    ced=["5.1.A.2", "5.1.A.3", "5.2.C.7", "5.2.D.1"],
    links=[
        ("OWASP Session Management Cheat Sheet",
         "https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html"),
        ("PortSwigger Web Security Academy: access control and privilege escalation",
         "https://portswigger.net/web-security/access-control"),
        ("MDN: Using HTTP cookies (security attributes)",
         "https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/Cookies"),
    ],
))

register(Lesson(
    id="web-idor",
    title="Insecure direct object reference (IDOR)",
    summary=("You read the admin's invoice by changing a number in the URL. The server "
             "checked that you were logged in, but never checked that the invoice was yours."),
    attacked=[
        "The weak link is a missing check in the invoice page. The app does "
        "authentication (are you logged in?) but skips authorization (are you allowed to "
        "see this particular record?):",
        Code("""
if not cookie("session"):
    return login_required()
invoice = invoices[int(query["id"])]     # any id the client asks for
return show(invoice)
""", "The vulnerable logic in the lab's web app"),
    ],
    how=[
        Code("""
GET /invoice?id=«1002»     ->  alice's own invoice
GET /invoice?id=«1001»     ->  the admin's invoice
""", "Same session, different id"),
        "The id is a direct reference to a database object, and the server returns "
        "whichever object is named. Invoice numbers that count up make it trivial to "
        "walk through every customer's data with a loop.",
        "In the OWASP Top 10 this family of bugs is 'Broken Access Control', the most "
        "common serious web application risk in the 2021 edition. In APIs it is called "
        "broken object level authorization (BOLA).",
    ],
    why=[
        "The developer assumed users would only follow the links the page shows them. "
        "The link to invoice 1001 is hidden from alice, but hiding a link is not a "
        "control: the URL is under the user's control.",
    ],
    defend=[
        "Check ownership on the server, for every request, at the point the object is loaded:",
        Code("""
invoice = invoices.get(invoice_id)
if invoice is None or (invoice.owner != session.user and session.role != "admin"):
    return not_found()        # same answer for 'missing' and 'not yours'
""", "The fixed lookup"),
        Bullets([
            "Better still, make the query itself scoped to the user, so another user's "
            "record cannot be loaded by mistake:  SELECT ... WHERE id = ? AND owner = ?",
            "Deny by default: a new page is inaccessible until a rule allows it.",
            "Random, unguessable ids (UUIDs) slow down enumeration, but they are not "
            "access control. Ids leak through links, logs and screenshots.",
            "Automated tests that log in as user A and request user B's objects, run on "
            "every change.",
        ]),
    ],
    detect=[
        "Enumeration is visible in access logs: one session requesting many different "
        "ids in sequence, often with a rising count of 403 or 404 responses. In this "
        "lab's log, your own requests show it:",
        Code("grep '/invoice' ~/cyberlab/logs/webapp.log"),
    ],
    ced=["5.1.A.3", "5.2.C.7", "5.2.D.1", "4.4.A.6"],
    links=[
        ("PortSwigger Web Security Academy: insecure direct object references",
         "https://portswigger.net/web-security/access-control/idor"),
        ("OWASP Top 10 (2021) A01: Broken Access Control",
         "https://owasp.org/Top10/A01_2021-Broken_Access_Control/"),
        ("OWASP Insecure Direct Object Reference Prevention Cheat Sheet",
         "https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html"),
    ],
))

register(Lesson(
    id="web-upload",
    title="Upload filter bypass",
    summary=("You uploaded a file the server would run as code, past a filter that "
             "blocked only the one extension its author thought of."),
    attacked=[
        "The weak link is the upload filter, a blocklist with a single entry:",
        Code("""
if filename.lower().endswith(".php"):
    return reject()
save(filename)
""", "The vulnerable check in the lab's web app"),
        "On a classic Apache + PHP server, the web server decides what to execute by "
        "file extension, and several extensions besides .php are commonly mapped to the "
        "PHP interpreter (.phtml, .php5, .phar and others). A file with one of those "
        "names, saved inside the web root, is a program anyone can run by visiting its "
        "URL: a web shell.",
    ],
    how=[
        Code("""
POST /upload   filename=«shell.php»      ->  403 rejected
POST /upload   filename=«shell.phtml»    ->  stored, and still executed as PHP
""", "The bypass"),
        "The file's content never mattered to the filter, only its name, and the name "
        "is chosen by the uploader. In a browser the name comes from the file you pick; "
        "with curl or an intercepting proxy you can set it to anything.",
        "Other common bypasses of weak upload filters: double extensions "
        "(shell.php.jpg on misconfigured servers), upper/lower case (shell.PhP), and a "
        "false Content-Type header (claiming image/jpeg).",
    ],
    why=[
        "A blocklist tries to enumerate what is dangerous, and it is always incomplete. "
        "The server also stored uploads where it executes code, under a name the "
        "attacker chose. Either mistake alone might be survivable; together they give "
        "remote code execution.",
    ],
    defend=[
        Bullets([
            "Allow-list instead of blocklist: accept only the few extensions the feature "
            "needs (for a profile photo: .jpg, .png) and reject everything else.",
            "Verify the content matches: check the file's signature (magic bytes), or "
            "better, re-encode images with an image library, which discards anything "
            "that is not image data.",
            "Never keep the user's filename. Store the file under a random name the "
            "server generates, with an extension the server chooses.",
            "Store uploads outside the web root or in object storage, and serve them "
            "from a location where script execution is disabled.",
            "Limit size, scan for malware, and require authentication to upload.",
        ]),
        Code("""
ALLOWED = {".jpg", ".jpeg", ".png"}
ext = Path(filename).suffix.lower()
if ext not in ALLOWED or not looks_like_image(data):
    return reject()
stored_name = secrets.token_hex(16) + ext        # not the user's name
(UPLOADS_OUTSIDE_WEBROOT / stored_name).write_bytes(data)
""", "A safer upload handler"),
    ],
    detect=[
        "Defenders watch upload directories for files with executable extensions, and "
        "access logs for requests to newly uploaded files, especially ones followed by "
        "unusual query strings (commands being passed to a web shell). File integrity "
        "monitoring flags new files appearing in the web root.",
    ],
    ced=["5.1.B.2", "5.5.B.2", "5.1.A.3"],
    links=[
        ("PortSwigger Web Security Academy: file upload vulnerabilities",
         "https://portswigger.net/web-security/file-upload"),
        ("OWASP File Upload Cheat Sheet",
         "https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html"),
        ("OWASP: Unrestricted File Upload",
         "https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload"),
    ],
))
