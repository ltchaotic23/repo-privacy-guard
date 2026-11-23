# Security policy

## Reporting a vulnerability

Please report security problems privately through GitHub: open this repository's
**Security** tab and choose **Report a vulnerability**. Please don't open a public issue
for them.

It helps to include what you found, the steps or a small input that shows it, and your
Python, Git and operating system versions. Use made-up values only, never real secrets or
personal details.

Examples of what counts:

- a way to make the guard print the text it matched
- crafted input that makes the guard crash, hang or let a commit or push through
- a workflow that gets more access than it declares
- the installer overwriting something without asking

A token format or personal detail that the guard simply doesn't know about isn't a
vulnerability. Please open an ordinary issue for it, with a made-up example.

## Supported versions

Only the latest version on the default branch gets fixes.
