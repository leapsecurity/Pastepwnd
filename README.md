# Pastepwnd

## Introduction
-----
Pastepwnd is a python based tool to help identify compromised email addresses and/or domains. Pastepwnd uses [HIBP](https://haveibeenpwned.com) and [Hacked Emails](https://hacked-emails.com) APIs to identify compromises. Compromised emails and domains are written to an HTML file along with links to their raw output (e.g., pastes) for easy reference.

## Installation
-----
Run `pip install -r requirements.txt` within the cloned Pastepwnd directory.

## Help
-----

```
Pastepwnd - A HIBP and Hacked Email wrapper by Jonathan Broche @LeapSecurity

optional arguments:
  -h, --help       show this help message and exit
  -v, --version    show program's version number and exit
  -e, --email EMAIL    An email or new line delimited file containing email
                   addresses to query against HIBP and Hacked Email.
  -d, --domain DOMAIN  A domain or new line delimited file containing domains to
                   query against HIBP.
  --html HTML Output result details to HTML file.
```

## Examples
-----

`python pastepwnd.py --email foo@acme.com`

`python pastepwnd.py --domain acme.com`

`python pastepwnd.py --email foo@acme.com --domain acme.com --html`

Provide Pastepwnd with a new line delimited file of email addresses or domain names.

`python pastepwnd.py --email emails.txt --domain domains.txt`

## Questions, Comments?
-----

Contact us at [@leapsecurity](https://twitter.com/leapsecurity) with any questions or features you'd like to see. For bugs submit an issue [here](https://github.com/leapsecurity/Pastepwnd/issues/new).