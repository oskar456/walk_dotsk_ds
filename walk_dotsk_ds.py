# /usr/bin/env python3

import csv
import time
from hashlib import sha1
from base64 import b32encode
from collections import OrderedDict, defaultdict
from operator import itemgetter
from pathlib import Path
import urllib.request
import urllib.error

import dns.name
from dns.rdtypes.ANY.NSEC3 import b32_normal_to_hex
import dns.message
import dns.query
import dns.rdatatype


def digest_to_ascii(digest):
    return b32encode(digest).translate(b32_normal_to_hex).decode("ascii")


def get_nsec3_hash(name, iterations=1, salt=None):
    wirename = dns.name.from_text(name).to_wire()
    if salt:
        salt = bytes.fromhex(salt)
        wirename += salt
    digest = sha1(wirename).digest()
    for i in range(iterations):
        if salt:
            digest += salt
        digest = sha1(digest).digest()
    return digest_to_ascii(digest)


def read_domains_txt(domainstxt):
    yield from csv.DictReader(
        (r for r in domainstxt if not r.startswith("--")), delimiter=";",
    )


def write_secured_csv(
    secureddomains,
    outpath="domains-secured.csv",
    domainstxt="domains.txt",
):
    outpath = Path(outpath)
    domainstxt = Path(domainstxt)
    with domainstxt.open(newline="") as inf, outpath.open("w") as outf:
        fieldnames = next(read_domains_txt(inf)).keys()
        inf.seek(0)
        writer = csv.DictWriter(outf, fieldnames)
        writer.writeheader()
        writer.writerows(
            r for r in read_domains_txt(inf)
            if r.get("domena") in secureddomains
        )


def generate_stats(
    securedcsv="domains-secured.csv",
    outpath="domains-stats.csv",
):
    securedcsv = Path(securedcsv)
    outpath = Path(outpath)
    regcount = defaultdict(int)
    with securedcsv.open(newline="") as inf:
        reader = csv.DictReader(inf)
        for row in reader:
            regcount[row.get("ID reg")] += 1
    with outpath.open("w") as outf:
        fieldnames = ["ID reg", "count"]
        writer = csv.writer(outf)
        writer.writerow(fieldnames)
        writer.writerows(
            sorted(regcount.items(), key=itemgetter(1), reverse=True,),
        )
        writer.writerow(["TOTAL", sum(regcount.values())],)


def update_domains_txt(
    url="https://sk-nic.sk/subory/domains.txt",
    path="domains.txt",
):
    path = Path(path)
    request = urllib.request.Request(url)
    if path.is_file():
        stat = path.stat()
        imsheader = time.strftime(
            "%a, %d %b %Y %H:%M:%S GMT", time.gmtime(stat.st_mtime),
        )
        request.add_header("If-Modified-Since", imsheader)
    try:
        with urllib.request.urlopen(request) as req:
            print("Downloading domains.txt…")
            path.write_bytes(req.read())
    except urllib.error.HTTPError as e:
        if e.code == 304:
            print("Current domains.txt is not modified")
        else:
            raise


def update_rainbow_dict(
    domainstxt="domains.txt",
    rainbowtable="domains-rainbow.tsv",
):
    domainstxt = Path(domainstxt)
    rainbowtable = Path(rainbowtable)
    if (
        rainbowtable.is_file()
        and rainbowtable.stat().st_mtime > domainstxt.stat().st_mtime
    ):
        print("Reusing old rainbow table")
        with rainbowtable.open(newline="") as csvfile:
            reader = csv.DictReader(csvfile, dialect="excel-tab")
            return OrderedDict((i.values() for i in reader))
    raindict = {get_nsec3_hash("sk"): "sk"}
    print("Computing the rainbow table…")
    with domainstxt.open(newline="") as inf:
        for r in read_domains_txt(inf):
            d = r["domena"]
            h = get_nsec3_hash(d)
            raindict[h] = d

    print("Sorting hashes…")
    raindict = OrderedDict(sorted(raindict.items()))
    with rainbowtable.open("w") as outf:
        writer = csv.writer(outf, dialect="excel-tab")
        writer.writerow(["hash", "domena"])
        writer.writerows(raindict.items())
    print("Done.")
    return raindict


def _next_odict_item(d, key):
    i = iter(d.items())
    for k, v in i:
        if k == key:
            try:
                return next(i)
            except StopIteration:
                return next(d.items())


def walk_nsec3(raindict, origin="sk"):
    nsec3cache = dict()
    secureddomains = set()
    originhash = get_nsec3_hash(origin)
    d = origin
    h = originhash
    print("Walking NSEC3 hashes…\n")
    iters, reqs = 0, 0
    while True:
        iters += 1
        if h not in nsec3cache:
            reqs += 1
            q = dns.message.make_query(f"\0.{d}.", "DS", want_dnssec=True)
            res = dns.query.tcp(q, "c.tld.sk")
            nsec3cache.update(
                (rrset.name.labels[0].decode("ascii").upper(), rrset[0])
                for rrset in res.authority
                if rrset.rdtype == dns.rdatatype.NSEC3
            )
        if dict(nsec3cache[h].windows)[0][5] & 0x10:
            # this owner has a DS record
            d = raindict[h]
            print(d)
            secureddomains.add(d)
        h = digest_to_ascii(nsec3cache[h].next)
        if h == originhash:
            break
        _, d = _next_odict_item(raindict, h)

    print("\nIterations: ", iters)
    print("DNS requests: ", reqs)
    print("DS records discovered: ", len(secureddomains))
    with open("domains-secured.txt", "w") as outf:
        for d in sorted(secureddomains):
            outf.write(d)
            outf.write("\n")
    return secureddomains


def main():
    update_domains_txt()
    raindict = update_rainbow_dict()
    secured = walk_nsec3(raindict)
    write_secured_csv(secured)
    generate_stats()


if __name__ == "__main__":
    main()
