import requests
import argparse
import validators
import re
from bs4 import BeautifulSoup


class CrtSh:

    CRTSH_DOMAIN = 'crt.sh'

    def check_connectivity(self, domain:
                           str = CRTSH_DOMAIN,
                           retcode: int = None) -> bool:
        """
            Task 1 & 4: Check if we can connect to a given domain.

            :param domain: domain to check for connectivity
            :type domain: str

            :param retcode: check for certain http status code.
            :type retcode: int

            :returns: true if crt.sh is alive, false if not
            :rtype: bool
        """
        try:
            domaintocheck = "https://{0}".format(domain)
            result = requests.get(domaintocheck)
            if retcode is not None:
                if result.status_code == retcode:
                    return True
                else:
                    return False
            else:
                return True
        except requests.exceptions.ConnectTimeout:
            return False
        except requests.exceptions.ConnectionError:
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

    def retrieve_cert_data(self, domain: str) -> dict:
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
            result = requests.get(url=searchurl, params=query)
            return result.json()
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

    def check_domains(self, domainstocheck: list) -> tuple:
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

        for domaintocheck in domainstocheck:
            online = self.check_connectivity(domaintocheck)
            if online:
                onlinelist.append(domaintocheck)
            else:
                offlinelist.append(domaintocheck)

        return (onlinelist, offlinelist)

    def scrape_domain(self, domain: str) -> str:
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
            response = requests.get(url)
            try:
                soup = BeautifulSoup(response.text, 'html.parser')
                if soup.title is not None:
                    return soup.title.text
                else:
                    return 'No <title> tag'
            except:
                return None
        except:
            return None
