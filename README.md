# Pastepwnd

## Introduction
-----
Pastepwnd helps identify compromised email addresses and/or domains. It is a python based wrapper for the [HIBP](https://haveibeenpwned.com) and [Canario](https://canar.io) services. Compromised emails/domains are written to an HTML file along with their respective pastes for easy reference.

## Installation
-----
Run `pip install -r requirements.txt` within the cloned Pastepwnd directory.

## Help
-----

```
Pastepwnd - A HIBP and Canario wrapper by Jonathan Broche (@g0jhonny)

optional arguments:
  -h, --help         show this help message and exit
  -v, --version      show program's version number and exit
  --email [string]   Query email(s) against HIBP for potential compromises.
  --domain [string]  Query domain(s) against HIBP for potential breaches.
  --file file        A new line delimited file containing email addresses or
                     domain names.
  --canario string   Provide a 64-character Canario API Key. Use Canario API's
                     'search' action to identify potential compromises.
```

## Examples
-----

Pastepwnd's basic usage quieries the HIBP API for a compromised email or domain name.

`python pastepwnd.py --email foo@bar.com`

`python pastepwnd.py --domain adobe.com`

Provide Pastepwnd with a new line delimited file of email addresses or domain names.

`python pastepwnd.py --email --file emails.txt`

Combine HIBP with Canario's API for increased results. You will need to [register](https://canar.io/register/) with Canario and obtain a valid API Key to use the service.

`python pastepwnd.py --email --file emails.txt --canario 540d7cf6bfd61324c520309d4dd61e4c8107a13...`

## Questions, Bugs, Praise?
-----

Contact me at [@g0jhonny](https://twitter.com/g0jhonny) with any questions or features you'd like to see. For bugs submit an issue [here](https://github.com/gojhonny/Pastepwnd/issues/new).
