#!/usr/bin/env python2
# Copyright (c) 2018 Jonathan Broche (@g0jhonny) @LeapSecurity

import requests, json, argparse, sys, re, time, os

class HackedEmails:
    def __init__(self):
        self.api = "https://hacked-emails.com/api"

    def request(self, email):
        url = self.api + "?q={}".format(email)
        r = requests.get(url)
        if r.status_code == 200:
            return r.json()        

class HIBP:
    def __init__(self):
        self.headers = {'User-Agent': 'Pastepwnd-Compromise-Check', 'api-version': '2'}

    def request(self, url):
        r = requests.get(url, headers=self.headers)
        if "Retry-After" in r.headers:
            print "  Sleeping for {}s to avoid HIBP lockout.".format(r.headers["Retry-After"])
            time.sleep(int(r.headers["Retry-After"])) #sleep to avoid HTTP 429/Rate Limiting
            r = requests.get(url, headers=self.headers)
        if r.status_code == 200:
            return r.json()

    def paste(self, email):
        return "https://haveibeenpwned.com/api/v2/pasteaccount/{email}".format(email=email)

    def breach(self, domain):
        return "https://haveibeenpwned.com/api/v2/breaches?domain={domain}".format(domain=domain)

class Workbench:
    def __init__(self):
        self.cachedurl = "https://webcache.googleusercontent.com/search?q=cache:"

    def format_paste(self, entity, email): #hibp paste      
        title = entity["Title"]
        date = entity["Date"]
        Id = entity["Id"]
        urls = []
        if len(Id) == 8: #pastebin ID
            pastebin = self.create_pastebinurl(Id)
            urls.append("<a href='{}' target='_blank'>Pastebin</a>".format(pastebin))
            urls.append("<a href='{}{}' target='_blank'>Cached View</a>".format(self.cachedurl, pastebin))
        else: #Id is a real URL
            urls.append("<a href='{}' target='_blank'>Source</a>".format(Id))
            urls.append("<a href='{}{}' target='_blank'>Cached View</a>".format(self.cachedurl, Id))

        return [title, email, date, urls]

    def format_breach(self, entity, domain): #hibp breach
        title = entity["Title"]
        date = entity["BreachDate"]
        desc = entity["Description"]
        pwncount = entity["PwnCount"]
        sensitive = entity["IsSensitive"]

        return [title, domain, date, desc, pwncount, sensitive]

    def format_hackedemail(self, breach, email):
        title = breach["title"]
        date = breach["date_created"]
        url = breach["source_url"]
        urls = []
        if url != "#":
            urls.append("<a href='{}' target='_blank'>Source</a>".format(url))
            urls.append("<a href='{}{}' target='_blank'>Cached View</a>".format(self.cachedurl, url))

        return [title, email, date, urls]

    def create_pastebinurl(self, Id):
        return "https://pastebin.com/raw.php?i={}".format(Id)

class Output:
    def __init__(self):
        pass

    def create_webpage(self, results):
        html = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>Pastepwnd</title>
            <style type="text/css">
                body { font-family: 'Helvetica Neue',Arial, Helvetica,sans-serif; background-color: #eee;}
                table {
                    background-color: #1d1f21;
                    border: 1px solid rgba(34,36,38,.15);
                    border-radius: 2px;
                    color: #fff;
                    text-align: left;
                    border-collapse: collapse;
                    font-size: 12px;
                    margin-bottom: 10px;}
                th, td {padding: 5px; border-bottom: 1px solid #ddd;}
                th {background-color: #f0b128; color: #fff;}
                tr:hover {background-color: #303336;}
                td {border-color: inherit; vertical-align: middle;}
                a {color: #f5ca6f;}
                hr {border-top: 1px solid #636c72 margin: 1.5rem 0};
            </style>
        </head>
        <body>
        <h2>Pastepwnd Breach Detector</h2>
        """

        html+= results
        html += "</body></html>"
        return html

    def create_domain_table(self, results):
        table = """
        <h4>Breaches by Site</h4>
        <table>
        <thead>
        <tr>
        <th>#</th>
        <th>Title</th>
        <th>Target</th>
        <th>Date</th>
        <th>Description</th>
        <th>Compromised Accounts</th>
        <th>Sensitive</th>
        </tr>
        </thead>
        <tbody>
        """
        for record in results:
            table += "<tr><td>{key}</td><td>{title}</td><td>{domain}</td><td>{date}</td><td>{desc}</td><td>{pwncount}</td><td>{sensitive}</td></tr>".format(key=results.index(record), title=record[0], domain=record[1], date=record[2], desc=record[3], pwncount=record[4], sensitive=record[5])
        table += "</tbody></table>"
        return table

    def create_email_table(self, results):
        table = """
        <h4>Breaches by Email</h4>
        <table>
        <thead>
        <tr>
        <th>#</th>
        <th>Title</th>
        <th>Email</th>
        <th>Date</th>
        <th>URLs</th>
        </tr>
        </thead>
        <tbody>
        """
        for record in results:
            table += "<tr><td>{key}</td><td>{title}</td><td>{email}</td><td>{date}</td><td>{urls}</td></tr>".format(key=results.index(record), title=record[0], email=record[1], date=record[2], urls=str(' | '.join(record[3])))
        table += "</tbody></table>"

        return table

    def write_file(self, html):
        with open("pastepwnd.html" , "w") as f:
            f.write(html)
        return os.path.abspath("pastepwnd.html")

def main():
    parser = argparse.ArgumentParser(description='Pastepwnd - A HIBP and Hacked Email wrapper by Jonathan Broche @LeapSecurity', version="1.0.1")  
    parser.add_argument('-e', '--email', help="An email or new line delimited file containing email addresses to query against HIBP and Hacked Email.")
    parser.add_argument('-d', '--domain', help="A domain or new line delimited file containing domains to query against HIBP.")
    parser.add_argument('--html', action='store_true', help="Output result details to HTML file.")

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    args = parser.parse_args()

    if not args.email and not args.domain:
        print "You didn't provide any work for me to do."
        sys.exit(1)

    print "\nPastepwnd {}\n".format(parser.version)

    hibp = HIBP()
    he = HackedEmails()
    workbench = Workbench()
    output = Output()    
    targets, results = [], []
    email_html, domain_html = "", ""

    if args.email:
        print "Status: Searching for Compromised Emails..."
        if os.path.isfile(args.email): #if file add emails
            with open (args.email) as f:
                for line in f.readlines():
                    targets.append(line.strip())
        else: #if not append the provided argument
            targets.append(args.email.strip())  
   
        for email in targets:
            if re.match(r"[^@]+@[^@]+\.[^@]+", email): #check for valid email
                response = hibp.request(hibp.paste(email)) #hibp reqeuest
                if response:
                    for entity in response:
                        results.append(workbench.format_paste(entity, email))
                he_response = he.request(email) #hacked-email.com request
                if he_response:
                    for breach in he_response["data"]:
                        results.append(workbench.format_hackedemail(breach, email))
            else: print "'{}' is not a valid email address.".format(email)
        if results:
            try:
                for record in results:
                    print "Title: {}, Date: {}".format(record[0], record[2])
            except UnicodeEncodeError as e:
                pass
            
            if args.html:
                email_html = output.create_email_table(results)
            results, targets = [], []
        else: print "No compromises identified for {} email.".format(args.email)
        

    if args.domain:
        print "Status: Searching for Compromised Domains..."
        if os.path.isfile(args.domain):
            with open(args.domain) as f:
                for line in f.readlines():
                    targets.append(line.strip())
        else:
            targets.append(args.domain.strip())

        for domain in targets:
            response = hibp.request(hibp.breach(domain))
            if response:
                for entity in response:
                    results.append(workbench.format_breach(entity, domain))
        if results:
            try:
                for record in results:
                    print "Title: {}, Date: {}, Pwnd Count: {}".format(record[0], record[2], record[4])
            except UnicodeEncodeError as e:
                pass

            if args.html:
                domain_html = output.create_domain_table(results)
        else: print "No compromises identified for {} domain.".format(args.domain)


    final_html = domain_html + email_html
    if final_html:
        file = output.write_file(output.create_webpage(final_html))
        print "\nHTML Results saved to '{}'\n".format(file)

if __name__ == '__main__':
    main()
