import requests
from threading import Thread
from queue import Queue

q = Queue()

def scan_subdomains(domain):
    global q
    subdomain = 0
    while True:
        try:
            # get the subdomain from the queue
            subdomain = q.get()
            # scan the subdomain
            url = f"http://{subdomain}.{domain}"
            try:
                requests.get(url)
            except requests.ConnectionError:
               print("\033[1;31;40m[*] Subdomain " + url + " Does Not Exist")
               pass
            else:
                print("\033[1;32;40m[*] Discovered subdomain:", url)
                ExistingSubs = open("ExistingSubdomains.txt","a")
                ExistingSubs.writelines(url + "\n")
            # we're done with scanning that subdomain
            q.task_done()
        except KeyboardInterrupt:
            break
def main(domain, n_threads, subdomains):
    global q

    # fill the queue with all the subdomains
    for subdomain in subdomains:
        q.put(subdomain)

    for t in range(n_threads):
        # start all threads
        worker = Thread(target=scan_subdomains, args=(domain,))
        # daemon thread means a thread that will end when the main thread ends
        worker.daemon = True
        worker.start()


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Faster Subdomain Scanner using Threads")
    parser.add_argument("domain", help="Domain to scan for subdomains without protocol (e.g without 'http://' or 'https://')")
    parser.add_argument("-l", "--wordlist", help="File that contains all subdomains to scan, line by line. Default is subdomains.txt",
                        default="subdomains.txt")
    parser.add_argument("-t", "--num-threads", help="Number of threads to use to scan the domain. Default is 10", default=10, type=int)
    
    args = parser.parse_args()
    domain = args.domain
    wordlist = args.wordlist
    num_threads = args.num_threads

    try:
        main(domain=domain, n_threads=num_threads, subdomains=open(wordlist).read().splitlines())
        q.join()
    except KeyboardInterrupt:
        exit(0)
