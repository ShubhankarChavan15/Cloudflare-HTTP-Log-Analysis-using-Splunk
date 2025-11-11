# Cloudflare-HTTP-Log-Analysis-using-Splunk
This project walks you through analyzing Cloudflare HTTP Request Logs to separate normal traffic from malicious activity. You’ll ingest the JSONL dataset, use field-aware SPL on ClientIP, URI, QueryString, Status, UserAgent, CacheStatus, WAFAction, RayID, and also practice parsing an embedded raw record with spath for flexible extraction.

 
## OBJECTIVE
* Ingest Cloudflare HTTP logs and analyze them with field-aware SPL.
* Detect brute force, SQLi, XSS, LFI, reconnaissance, and interpret WAF/cache signals.
* Practice parsing embedded raw event JSON with spath.

## VALIDATE:
```spl
index=cloudflare_lab | head 5
```
Inspect a few raw events to learn the JSON structure.

## Step by Step guide
## Task#1 — Brute Force Login Attempts
GOAL: Detect repeated failed login attempts to /login.php, /wp-login.php, /admin/login often return 401/403.
```spl
index=cloudflare_lab (URI="/login.php" OR URI="/wp-login.php" OR URI="/admin/login") (Status=401 OR Status=403)
| stats count AS attempts by ClientIP, URI, UserAgent
| sort -attempts
```
Here
* URI pinpoints login endpoints.
* Status 401/403 surfaces failed logins to flag brute force sources.

## TASK #2 — SQL INJECTION (SQLi) ATTEMPTS
GOAL: Find SQL payloads like ' OR '1'='1, UNION SELECT.
```spl
index=cloudflare_lab (URI="*' OR '1'='1*" OR URI="*UNION SELECT*")
| stats count AS hits by ClientIP, URI, UserAgent, WAFAction
| sort -hits
```
Here
* URI carries injected payloads.
* WAFAction shows whether Cloudflare logged/blocked/challenged the request.
  
## Task#3 — Cross-Site Scripting (XSS)
GOAL: Detect <script> or URL-encoded XSS payloads and onerror= patterns.
```spl
index=cloudflare_lab (URI="*<script>*" OR URI="*%3Cscript%3E*")
| stats count AS hits by ClientIP, URI, UserAgent, Status
| sort -hits
```
Here
* URI contains the JS payload.
* Status reveals whether origin/edge returned a success or error.
  
## Task#4 — Local File Inclusion (LFI) / Directory Traversal
GOAL: Detect attempts to read local files or use ../ traversal.
```spl
index=cloudflare_lab (URI="*/etc/passwd*" OR URI="*../*" OR URI="*..%2F*")
| stats count AS attempts by ClientIP, URI, Status
| sort -attempts
```
Here
* URI pattern-matches sensitive file paths and traversal sequences.
* Status indicates exposure vs denial.

## Task#5 — Recon & Admin Path Scanning
GOAL: Find enumeration of admin interfaces and sensitive files.
```spl
index=cloudflare_lab (URI="/admin" OR URI="/phpmyadmin" OR URI="/wp-admin" OR URI="/.git/HEAD" OR URI="/server-status")
| stats count AS hits by ClientIP, URI, Status
| sort -hits
```
Here
* URI targets common admin interfaces.
* Status shows whether attempts were blocked, missing, or (worse) allowed.

## Conclusion
