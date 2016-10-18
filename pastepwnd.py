#!/usr/bin/env python2
# Copyright (c) 2016 Jonathan Broche (@g0jhonny)

import requests, json, argparse, sys, re, time, os

class Canario:
    def __init__(self, api_key):
        self.api_key = api_key

    def request(self, url):
        r = requests.get(url)
        if r.status_code == 200:
            return r.json()        

    def search(self, query, bang): #!email or !host
        return "https://canar.io/_api/?key={api_key}&action=search&query=!{bang} {query}".format(api_key = self.api_key, bang=bang, query=query)

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

    def format_search(self, target, entity): #canario search action
        title = entity["title"]
        refId = entity["referenceid"]
        url = "<a href='https://canar.io/view/{}' target='_blank'>Source</a>".format(refId)
        return [title, target, url]

    def create_pastebinurl(self, Id):
        return "https://pastebin.com/raw.php?i={}".format(Id)

class Output:
    def __init__(self):
        pass

    def create_webpage(self, hibp_table, canario_table=""):
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
                    width: 80%;
                    margin-bottom: 10px;}
                th, td {padding: 5px; border-bottom: 1px solid #ddd;}
                th {background-color: #ee8c25; color: #fff;}
                tr:hover {background-color: #6c737a;}
                td {border-color: inherit; vertical-align: middle;}
                a {color: #8f9c6c;}
            </style>
        </head>
        <body>
        <h2>PastePwnd</h2>
        """

        html+= hibp_table
        if canario_table:
            html+= canario_table
        if not hibp_table and not canario_table: 
            html+= "<p>No results to display.</p>"
        html += "</body></html>"
        return html

    def create_breach_table(self, results):
        table = """
        <h4>Have I Been Pwnd Data</h4>
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

    def create_paste_table(self, results):
        table = """
        <h4>HIBP Results</h4>
        <table>
        <thead>
        <tr>
        <th>#</th>
        <th>Title</th>
        <th>Target</th>
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

    def create_canario_table(self, results):
        table = """
        <h4>Canario Results</h4>
        <table>
        <thead>
        <tr>
        <th>#</th>
        <th>Title</th>
        <th>Target</th>
        <th>URL</th>
        </tr>
        </thead>
        <tbody>
        """

        for record in results:
            table += "<tr><td>{key}</td><td>{title}</td><td>{target}</td><td>{url}</td></tr>".format(key=results.index(record), title=record[0], target=record[1], url=record[2])
        table += "</tbody></table>"
        return table

    def write_file(self, html):
        with open("pastepwnd.html" , "w") as f:
            f.write(html)
        return os.path.abspath("pastepwnd.html")

def main():
    parser = argparse.ArgumentParser(description='Pastepwnd - A HIBP and Canario wrapper by Jonathan Broche (@g0jhonny)', version="1.0.0")  
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument('--email', nargs='?', default='', help="Query email(s) against HIBP for potential compromises.")
    action.add_argument('--domain', nargs='?', default='', help="Query domain(s) against HIBP for potential breaches.")
    parser.add_argument('--file', metavar="file", help="A new line delimited file containing email addresses or domain names.")
    parser.add_argument('--canario', metavar="string", help="Provide a 64-character Canario API Key. Use Canario API's 'search' and 'view' actions to identify potential compromises.")

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    args = parser.parse_args()

    if not args.file and not args.email and not args.domain:
        print "You didn't provide any work for me to do."
        sys.exit(1)

    print "\nPastepwnd {}\n".format(parser.version)

    hibp = HIBP()
    workbench = Workbench()
    output = Output()
    if args.canario: canario = Canario(args.canario)
    targets, results, cresults = [], [], []
    hibp_html, chtml = "", ""

    if args.file:
        with open(args.file) as f:
            for line in f.readlines():
                targets.append(line.strip())

    print "Status: Searching HIBP..."
    if args.email or args.email == None:
        if args.email: targets.append(args.email.strip())        
        for email in targets:
            if re.match(r"[^@]+@[^@]+\.[^@]+", email): #check for valid email
                response = hibp.request(hibp.paste(email))
                if response:
                    for entity in response:
                        results.append(workbench.format_paste(entity, email))

            else: print "'{}' is not a valid email address.".format(email)
        if results:
            hibp_html = output.create_paste_table(results)

    if args.domain or args.domain == None:
        if args.domain: targets.append(args.domain.strip())
        for domain in targets:
            response = hibp.request(hibp.breach(domain))
            if response:
                for entity in response:
                    results.append(workbench.format_breach(entity, domain))
        if results:
            hibp_html = output.create_webpage(output.create_breach_table(results))

    if args.canario:
        print "Status: Searching Canario...\n"
        if args.email or args.email == None:
            bang = "email"
        else: bang = "host"
        try:
            for target in targets: #domain or emails
                response = canario.request(canario.search(target, bang))
                if response:
                    for entity in response["data"]["results"]["results"]:
                        cresults.append(workbench.format_search(target, entity))
        except KeyError as e:
            print "Canario Search Skipped. Provide a valid Canario API Key.\n"
            pass

        if cresults:
            chtml = output.create_canario_table(cresults)

    if results or cresults:
        file = output.write_file(output.create_webpage(hibp_html, chtml))
        print "Completed. {} Pastes found.".format(len(results)+len(cresults))
        print "Results saved to '{}'\n".format(file)
    else: print "Completed. No results found."

if __name__ == '__main__':
    try:
        main()
    except IOError as e:
        print e
    except Exception as e:
        print e
