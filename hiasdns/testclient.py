from os.path import expanduser
import random

import subprocess

userhome = expanduser("~")
testfile = userhome + "/.hiasdns/testurls.txt"

with open(testfile, "r") as f:
    urllist = f.readlines()
urllist = [url.rstrip() for url in urllist]

#nslookup -port=5853 orf.at localhost

l0 = len(urllist)
while True:
    url = urllist[random.randint(0, l0-1)]
    

    
    process = subprocess.Popen(["nslookup", "-port=5853" , url, "localhost"], stdout=subprocess.PIPE)
    output = process.communicate()[0].decode().split("\n")
    l = []
    for o in output:
        if o.startswith("Address: "):
            l.append(o.replace('Address: ',''))
    print(url + " -->", l)
    # break
    