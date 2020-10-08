import aiohttp
import asyncio
import argparse
import validators
import re
from bs4 import BeautifulSoup


class CrtSh:

    CRTSH_DOMAIN = 'crt.sh'
    session = None

    def __init__(self):
        """
            Class constructor

            :param session: aiohttp ClientSession object
            :type session: ClientSession
        """
        self.session = aiohttp.ClientSession()

    async def aio_check_connectivity(self, domain:
                                     str = CRTSH_DOMAIN,
                                     retcode: int = None) -> bool:
        """
            Task 8a: Check if we can connect to a given domain, asynchronously

            :param domain: domain to check for connectivity
            :type domain: str

            :param retcode: check for certain http status code.
            :type retcode: int

            :returns: true if domain is alive, false if not
            :rtype: bool
        """
        result = await self.session.request(method='GET',
                                            url=domain)

        if result is not None:
            return result.status
        else:
            return result

    async def check_connectivity(self, domain:
                           str = CRTSH_DOMAIN,
                           retcode: int = None) -> bool:
        """
            Task 1 & 4: Check if we can connect to a given domain.

            :param domain: domain to check for connectivity
            :type domain: str

            :param retcode: check for certain http status code.
            :type retcode: int

            :returns: true if domain is alive, false if not
            :rtype: bool
        """
        try:
            domaintocheck = "https://{0}".format(domain)

            result = await self.aio_check_connectivity(domaintocheck, retcode)

            if retcode is not None:
                if result == retcode:
                    return True
                else:
                    return False
            else:
                return True
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
            result = await self.session.request(method='GET',
                                                url=searchurl,
                                                params=query)

            return await result.json()
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
            match = re.match(subdomainregex, domaintocheck, flags=re.IGNORECASE)
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
        task_semaphore = asyncio.Semaphore(200)

        for domaintocheck in domainstocheck:
            #print("Adding {0} to tasklist".format(domaintocheck))
            checktask = asyncio.create_task(self.check_connectivity(domaintocheck), name=domaintocheck)
            tasklist.append(checktask)

        async with task_semaphore:
            checkresults = await asyncio.gather(*tasklist)

        for task in tasklist:
            domain = task.get_name()
            if task.result:
                onlinelist.append(domain)
            else:
                offlinelist.append(domain)

        return (onlinelist, offlinelist)

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
            response = await self.session.request(method='GET',
                                                  url=url)
            try:
                soup = BeautifulSoup(await response.text(), 'html.parser')
                if soup.title is not None:
                    return soup.title.text
                else:
                    return 'No <title> tag'
            except:
                return None
        except:
            return None
