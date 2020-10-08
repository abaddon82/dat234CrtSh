import sys
from CrtSh import CrtSh
import asyncio
import multiprocessing
from aiohttp import ClientSession


async def main():

    # session = ClientSession()
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
                        # return await session.close()
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
                        # return await session.close()
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

                    # return await session.close()
                else:
                    print("done, but there are no certificates issued to this domain.")
                    # return await session.close()
            else:
                print('domain not found!')
                #return await session.close()
        else:
            print("looks like it's down, try again later")
            # await session.close()
            sys.exit(-1)
    return None

if __name__ == "__main__":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    result = asyncio.run(main())
