# Security Policy

Sable is security-sensitive infrastructure. Thank you for reporting potential
vulnerabilities privately so they can be investigated and fixed before public
disclosure.

## Supported versions

Sable is currently pre-1.0. Security fixes are developed against `main` and
released in the newest available version.

| Version | Security updates |
| --- | --- |
| Latest published release | Supported |
| Older releases | Not supported; upgrade to the latest release |
| Development builds | Best effort; reproduce against current `main` when possible |

## Reporting a vulnerability

Use [GitHub private vulnerability reporting](https://github.com/drudge/sable/security/advisories/new)
when it is available. If the private form is unavailable, email
[nick@penree.com](mailto:nick@penree.com) with the subject **Sable Security**.

Do not open a public issue, discussion, or pull request containing vulnerability
details. Include as much of the following as possible in the private report:

- The affected Sable version, commit, deployment type, and operating system
- The affected component and required configuration
- Reproduction steps or a minimal proof of concept
- The security impact and realistic attack scenario
- Relevant logs, traces, or screenshots with secrets and personal data removed
- Any suggested remediation or temporary mitigation
- Whether and how you would like to be credited

## Response process

The project aims to acknowledge a report within three business days and provide
an initial assessment within seven business days. Complex issues may take
longer to reproduce or remediate; material progress updates will be shared with
the reporter at least every 14 days while work continues.

When a report is confirmed, the project will coordinate a fix, regression
coverage, release, and GitHub security advisory. Please allow a reasonable
remediation window before public disclosure. Reporters will be credited in the
advisory when requested.

## Responsible testing

Please act in good faith and:

- Test only systems and data you own or have explicit permission to use
- Minimize access to data and stop testing if sensitive information is exposed
- Avoid denial of service, social engineering, spam, persistence, and data
  destruction or exfiltration
- Use the least disruptive proof of concept that demonstrates the issue
- Delete any data obtained during research after the report is resolved

Reports about an upstream dependency should normally be sent to that project.
They are in scope for Sable when its specific use of the dependency creates a
demonstrable vulnerability. Automated scanner output without a reachable impact
is useful context but may not by itself establish a Sable vulnerability.

Sable does not currently operate a paid bug-bounty program.
