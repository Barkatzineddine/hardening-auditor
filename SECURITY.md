# Security policy

## Reporting a vulnerability

Please report vulnerabilities privately through GitHub:
**Security tab → Report a vulnerability** on this repository, or directly at
<https://github.com/Barkatzineddine/hardening-auditor/security/advisories/new>.

Do not open a public issue for security problems. You will get an acknowledgement within
5 working days, and a fix or mitigation plan once the report is confirmed.

## Scope

- The collectors (`collectors/`) run with administrator or root rights on production servers.
  Any way to make them change the system, execute untrusted input or send data off the machine
  is a vulnerability.
- The HTML report must not run code or load resources from an audited value (host name, file
  name, service name...). It is protected by output escaping and a Content Security Policy
  that only allows its own inline script and style, identified by their hashes.

## Supported versions

Only the latest commit on `main` is supported.
