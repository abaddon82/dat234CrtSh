# dat234CrtSh
In this task, you are supposed to write a script that will find subdomains for any kind of domain, write validation checks to validate if the domains both you find and search for are valid, and check if the domains are  "Alive" and responding.

All tasks need to be in one.py file, each task needs to be called as a function inside the CrtSh class.
You also need to comment on each function with the use of docstrings, as described in PEP257.

Try also to follow the style guide and type hints

PEP8
PEP484
Example Boilerplate: https://loot.datapor.no/d34a236e-820c-49d4-84d4-2113dd766f8b.py

You need to use at least requests and argparse for the assignment.

Task 1-6 is Mandatory, but it's recommended to do all tasks.

In this task, you are supposed to write a script that will find subdomains for any kind of domain, write validation checks to validate if the domains both you find and search for are valid, and check if the domains are  "Alive" and responding.

1. Visit the site crt.sh with the use of requests and check that it gives back 200 OK, and the program should stop if it doesn't give back 200 OK.
2. Make it able to take in an argument with argparse to which domain it should search certificate records for
  * Example: python main.py --domain betauia.net
3. Print out all the valid subdomains found in the certificates for the domain. (hint, use regex expression to check if the domain is valid.)
4. Check each subdomain, and see if it's "alive" meaning it gives a valid HTTP response code, and if it doesn't respond at all it should be seen as "not alive."
5. Store all domains that give a response in a list, and all other domains that don't give a response back in a separate list.
6. At the end of the program, print out the two lists and calculate a diff on how many domains were alive and responding to total domains.
7. Visit all the alive URLs and grep the title of the site, and print the title + domain to a JSON file.
8. Make the program Async, with the use of Asyncio.
9. Make the program use multiprocessing to go suuuper fast! SONIC GOTTA GO FAAAAAAAAAAAST
10. SEVDSy4uLnlvdSBoYXZlIGRvbmUgYWxsIHRoZSBvdGhlciB0YXNrcywgeW91IHRydWx5IGFyZSBhIHB5dGhvbiBqZWRpIG1hc3Rlci4KQnV0IGNhbiB5b3UgbWFrZSBtYWtlIHlvdXIgcHl0aG9uIHByb2dyYW0gaW4gT05FIGxpbmUhCgpTdWJtaXQgb25lbGluZXIgYXMgYSBzZXBlcmF0ZSBmaWxlLgpHb29kIEx1Y2su
11. DAT234{4lw4ys_try_t0_r34d_th3_wh0l3_task}

**You must also write a small report of min 100 andd max 666 words(± 10%) explaining how the group proceeded to solve the task, and what problems you encountered in solving the task 🙃**
