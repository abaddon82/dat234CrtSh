import sys
from CrtSh import CrtSh
import asyncio
from aiohttp import ClientSession


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
                    onlinelist, offlinelist = await crtsh.check_domains(domainstocheck)
                    print("\nOnline domains:\n---------------\n")
                    async with crtsh.session:
                        for domain in onlinelist:
                            title = await crtsh.scrape_domain(domain)
                            print("{0} ({1})".format(domain, title))

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

if __name__ == "__main__":
    asyncio.run(main())
