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
import random
import socket
from contextlib import contextmanager

import dns.name
from dns.rdtypes.ANY.NSEC3 import b32_normal_to_hex
import dns.message
import dns.query
import dns.rdatatype
import dns.resolver


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
    secureddomains,
    domainstxt="domains.txt",
    outpath="domains-stats.csv",
):
    domainstxt = Path(domainstxt)
    outpath = Path(outpath)

    class Count():
        secure = 0
        insecure = 0

    regcount = defaultdict(Count)
    with domainstxt.open(newline="") as inf:
        for row in read_domains_txt(inf):
            if row.get("domena") in secureddomains:
                regcount[row.get("ID reg")].secure += 1
            else:
                regcount[row.get("ID reg")].insecure += 1
    with outpath.open("w") as outf:
        fieldnames = [
            "ID reg", "secure domains", "insecure domains",
            "percent secure",
        ]
        writer = csv.writer(outf)
        writer.writerow(fieldnames)
        writer.writerows(
            sorted(
                (
                    (
                        k, v.secure, v.insecure,
                        round(100*v.secure/(v.secure + v.insecure), 2),
                    )
                    for k, v in regcount.items()
                ),
                key=itemgetter(1, 2),
                reverse=True,
            ),
        )
        totalsecure = sum((v.secure for v in regcount.values()))
        totalinsecure = sum((v.insecure for v in regcount.values()))
        writer.writerow(
            [
                "TOTAL", totalsecure, totalinsecure,
                round(100*totalsecure/(totalsecure + totalinsecure), 2),
            ],
        )


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
        rainbowtable.is_file() and
        rainbowtable.stat().st_mtime > domainstxt.stat().st_mtime
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


@contextmanager
def dns_socket(host, port=53):
    """Context manager for getting TCP DNS connection"""
    ai = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    for af, st, proto, _, sockaddr in ai:
        try:
            s = socket.socket(af, st, proto)
            s.connect(sockaddr)
        except OSError:
            continue
        break
    print("Connected to", sockaddr)
    try:
        yield s
    finally:
        s.close()


def tcp_query(socket, q):
    dns.query.send_tcp(socket, q.to_wire())
    r, _ = dns.query.receive_tcp(socket)
    if not q.is_response(r):
        raise dns.query.BadResponse
    return r


def _next_odict_item(d, key):
    i = iter(d.items())
    for k, v in i:
        if k == key:
            try:
                return next(i)
            except StopIteration:
                return next(d.items())


def _guess_next_domain(d, key):
    for k, v in d.items():
        if k > key:
            return v


def walk_nsec3(raindict, origin="sk"):
    resolver = dns.resolver.Resolver()
    nsset = resolver.query(f"{origin}.", dns.rdatatype.NS)
    nameserver = random.choice([ns.target.to_text() for ns in nsset.rrset])
    print("Using nameserver", nameserver)
    nsec3cache = dict()
    secureddomains = set()
    originhash = get_nsec3_hash(origin)
    d = origin
    h = originhash
    print("Walking NSEC3 hashes…\n", flush=True)
    iters, reqs, brokes, unknowns = 0, 0, 0, 0
    with dns_socket(nameserver) as s:
        while True:
            iters += 1
            if h not in nsec3cache:
                reqs += 1
                # print("Querying", d)
                q = dns.message.make_query(f"{d}.", "DS", want_dnssec=True)
                res = tcp_query(s, q)
                ns3rr = [
                    (rrset.name.labels[0].decode("ascii").upper(), rrset[0])
                    for rrset in res.authority
                    if rrset.rdtype == dns.rdatatype.NSEC3
                ]
                nsec3cache.update(ns3rr)
                if [
                    rrset
                    for rrset in res.answer
                    if rrset.rdtype == dns.rdatatype.DS
                ]:
                    print(d, "discovered directly")
                    secureddomains.add(d)
                    h = get_nsec3_hash(d)
                    _, d = _next_odict_item(raindict, h)
                    continue
                if h not in nsec3cache and len(ns3rr) > 0:
                    newh = [k for k, v in ns3rr if k > h][0]
                    print("Broken NSEC3 chain: expected", h, "got", newh)
                    brokes += 1
                    h = newh

            if dict(nsec3cache[h].windows)[0][5] & 0x10:
                # this owner has a DS record
                if h in raindict:
                    d = raindict[h]
                else:
                    d = f"UNKNOWN_{h}"
                    unknowns += 1
                print(d, flush=True)
                secureddomains.add(d)
            h = digest_to_ascii(nsec3cache[h].next)
            if h == originhash:
                break
            if h in raindict:
                _, d = _next_odict_item(raindict, h)
            else:
                d = _guess_next_domain(raindict, h)
                print("Next domain guessed:", d)

    print("\nIterations: ", iters)
    print("DNS requests: ", reqs)
    print("DS records discovered: ", len(secureddomains))
    print("Unknown domain names: ", unknowns)
    print("Broken NSEC3 chain incidents: ", brokes)
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
    generate_stats(secured)


if __name__ == "__main__":
    main()
