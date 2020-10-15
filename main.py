import sys
import asyncio
import aiohttp
import argparse
import validators
import re
from bs4 import BeautifulSoup


class CrtSh:

    CRTSH_DOMAIN = 'crt.sh'

    def __init__(self):
        """
            Class constructor
        """
    async def aio_check_connectivity(self, domain:
                                     str = CRTSH_DOMAIN,
                                     retcode: int = None,
                                     silent: bool = True) -> bool:
        """
            Task 8a: Check if we can connect to a given domain, asynchronously

            :param domain: domain to check for connectivity
            :type domain: str

            :param retcode: check for certain http status code.
            :type retcode: int

            :param silent: do not print results to screen.
            :type silent: bool

            :returns: true if domain is alive, false if not
            :rtype: bool
        """
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url=domain) as response:
                    if response is not None:
                        if not silent:            
                            print("{0}: OK ({1})".
                                  format(domain, response.status))
                        return response.status
                    else:
                        if not silent:
                            print("{0}: timeout, skipping".
                                  format(domain))
                        return response
        except aiohttp.client_exceptions.ClientConnectorCertificateError as ex:
            if not silent:
                print("{0}: Certificate validation error, skipping".
                      format(domain))
            return None
        except aiohttp.client_exceptions.ClientConnectorError as ex:
            if ex.errno == 11001:
                if not silent:
                    print("{0}: did not resolve, skipping".format(domain))
            elif ex.errno == 22:
                if not silent:
                    print("{0}: connection refused, skipping".format(domain))
            else:
                if not silent:
                    print("{0}: connection error: {1}".
                          format(domain, ex.strerror))
            return None
        except aiohttp.client_exceptions.ClientConnectionError as ex:
            if ex.errno == 11001:
                if not silent:
                    print("{0}: did not resolve, skipping".format(domain))
            else:
                if not silent:
                    print("{0}: Error: {1}: {2}".
                          format(domain, type(ex).__name__, ex.args))
            return None
        except OSError as ex:
            if not silent:
                print("{0}: unknown error: {1}: {2}".
                      format(domain, type(ex).__name__, ex.args))
            return None
        except Exception as ex:
            if not silent:
                print("{0}: unknown error: {1}: {2}".
                      format(domain, type(ex).__name__, ex.args))
            return None

    async def check_connectivity(self, domain:
                                 str = CRTSH_DOMAIN,
                                 retcode: int = None,
                                 silent: bool = True) -> bool:
        """
            Task 1 & 4: Check if we can connect to a given domain.

            :param domain: domain to check for connectivity
            :type domain: str

            :param retcode: check for certain http status code.
            :type retcode: int

            :param silent: do not print results to screen.
            :type silent: bool

            :returns: true if domain is alive, false if not
            :rtype: bool
        """
        try:
            domaintocheck = "https://{0}".format(domain)

            result = await self.aio_check_connectivity(domaintocheck,
                                                       retcode,
                                                       silent)

            if retcode is not None:
                if result == retcode:
                    return True
                else:
                    return False
            else:
                if result is not None:
                    return True
                else:
                    return False
        except:
            return False

    def parse_commandline(self, argv: list) -> str:
        """
            Task 2: Parse command line for which domain to check.

            :param argv: list of command line arguments to parse
            :type argv: list

            :returns: FQDN to check
            :rtype: str
        """
        parser = argparse.ArgumentParser(
                                        description='Process issued\
                                        certificates for a\
                                        domain through crt.sh.')
        parser.add_argument('domain', help='Domain to process')

        namespace = parser.parse_args(argv[1:])
        if validators.domain(namespace.domain):
            return namespace.domain
        else:
            return None

    async def retrieve_cert_data(self, domain: str) -> dict:
        """
            Task 3a: Retrieve list of issued certificates to be analyzed.

            :param domain: Domain to retrieve certificates for.
            :type domain: str

            :returns: A dictionary with certificate data
            :rtype: dict
        """
        try:
            query = {'output': 'json', 'q': domain}
            searchurl = "https://{0}".format(CrtSh.CRTSH_DOMAIN)

            async with aiohttp.ClientSession() as session:
                async with session.get(url=searchurl,
                                       params=query) as response:
                    return await response.json()
        except:
            return None

    def sanitize_cert_data(self, certdata: dict) -> dict:
        """
            Task 3b: Sanitize certificate data for further analysis.

            :param certdata: dictionary of certificate information retrieved from crt.sh
            :type certdata: dict

            :returns: A new, sanitized dictionary of certificate data
            :rtype: dict
        """

        certdict = {}

        if certdata is not None:
            tmp_certlist = []
            for cert in certdata:
                tmp_certlist.append(cert['common_name'])
                if cert['name_value'] is not None:
                    tmp_sans = cert['name_value'].split(sep="\n")
                    for tmp_san in tmp_sans:
                        tmp_certlist.append(tmp_san)
            certset = set(tmp_certlist)
            for cert in certset:
                certinfodict = {}

                certinfodict['valid'] = validators.domain(cert) or False
                certdict[cert] = certinfodict

            return certdict
        else:
            return None

    def get_subdomains(self, domain: str, domainlist: list) -> list:
        """
            Task 3c: Return valid subdomains for a domain from a list of domains.

            :param domain: domain name to check for subdomains
            :type domain: str

            :param domainlist: list of domain names to check
            :type domainlist: list

            :returns: A new list with only the subdomains remaining
            :rtype: list
        """

        subdomainlist = []

        if len(domainlist) == 0:
            return None

        for domaintocheck in domainlist:
            domainregexed = domain.replace('.', '\\.')
            subdomainregex = r".*{0}".format(domainregexed)
            match = re.match(subdomainregex,
                             domaintocheck,
                             flags=re.IGNORECASE)
            if match is not None:
                subdomainlist.append(domaintocheck)

        return subdomainlist

    async def check_domains(self, domainstocheck: list) -> tuple:
        """
            Task 5: Check list of domains for connectivity

            :param domainstocheck: list of domains to check
            :type domainstocheck: list

            :returns: Tuple separating online domains from offline domains
            :rtype: tuple
        """

        if domainstocheck is None or len(domainstocheck) == 0:
            return None

        onlinelist = []
        offlinelist = []

        tasklist = []

        try:
            for domaintocheck in domainstocheck:
                checktask = asyncio.create_task(
                    self.check_connectivity(domaintocheck), name=domaintocheck)
                tasklist.append(checktask)

            result = await asyncio.gather(*tasklist)

            for task in tasklist:
                domain = task.get_name()
                if task.result():
                    onlinelist.append(domain)
                else:
                    offlinelist.append(domain)

            return (onlinelist, offlinelist)
        except:
            return (None, None)

    async def scrape_domain(self, domain: str) -> str:
        """
            Task 7: Scrape domain web site title

            :param domain: domain to scrape
            :type domain: str

            :returns: String with the title of the page, or None
            :rtype: str
        """

        if domain is None:
            return None

        try:
            url = "https://{0}/".format(domain)

            async with aiohttp.ClientSession() as session:
                async with session.get(url=url) as response:
                    try:
                        data = await response.text()
                        if data:
                            soup = BeautifulSoup(data, 'html.parser')
                            if soup.title is not None:
                                return soup.title.text
                            else:
                                return 'No <title> tag'
                        else:
                            return 'No HTML data'
                    except:
                        return 'No HTML data'
        except:
            return None


async def main():

    crtsh = CrtSh()
    domain = crtsh.parse_commandline(sys.argv)

    if domain:
        print("Checking connectivity to {0}...".format(CrtSh.CRTSH_DOMAIN),
              end='', flush=True)

        if await crtsh.check_connectivity(retcode=200):
            print('all good!')
            print("Retrieving certificates for domain {0}...".format(domain),
                  end='', flush=True)
            certdata = await crtsh.retrieve_cert_data(domain)
            if certdata is not None:
                sanitized_certdata = crtsh.sanitize_cert_data(certdata)
                domainstocheck = crtsh.get_subdomains(domain, list(
                                                      filter(lambda domain:
                                                             sanitized_certdata
                                                             [domain]['valid'],
                                                             sanitized_certdata
                                                             )))
                if domainstocheck:
                    print('done! Checking domains...')
                    try:
                        onlinelist, offlinelist =\
                            await crtsh.check_domains(domainstocheck)
                    except:
                        print("Error while checking domain status")
                        sys.exit(-1)

                    print("\nOnline domains:\n---------------\n")
                    tasklist = []
                    try:
                        for domain in onlinelist:
                            scrapetask =\
                                asyncio.create_task(
                                    crtsh.scrape_domain(domain),
                                    name=domain)
                            tasklist.append(scrapetask)

                        result = await asyncio.gather(*tasklist)
                        for task in tasklist:
                            domain = task.get_name()
                            if task.result():
                                print("{0} ({1})".format(domain,
                                                         task.result()))
                            else:
                                print("{0}".format(domain))
                    except:
                        print("Error grabbing domain banners!")
                        sys.exit(-1)

                    print("\nOffline domains:\n----------------\n")
                    for domain in offlinelist:
                        print(domain)

                    onlinecount = len(onlinelist)
                    offlinecount = len(offlinelist)
                    totalcount = onlinecount + offlinecount

                    percentageonline = (onlinecount / totalcount) * 100

                    print("\n\n{0} / {1} ({2:.4g}%) domains were online when we checked!\n".format(
                        onlinecount, totalcount, percentageonline
                    ))
                else:
                    print("done, but there are no certificates issued to this domain.")
            else:
                print('domain not found!')
        else:
            print("looks like it's down, try again later")
            sys.exit(-1)
    return None

if __name__ == "__main__":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    result = asyncio.run(main())
