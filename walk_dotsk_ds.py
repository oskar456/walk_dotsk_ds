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
import sys
from itertools import tee, zip_longest

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
    """Context manager for getting UDP DNS connection"""
    ai = socket.getaddrinfo(host, port, type=socket.SOCK_DGRAM)
    for af, st, proto, _, sockaddr in ai:
        try:
            s = socket.socket(af, st, proto)
            s.connect(sockaddr)
        except OSError:
            continue
        break
    print("Sending to", sockaddr[0])
    try:
        yield s
    finally:
        s.close()


def udp_query(socket, q):
    dns.query.send_udp(socket, q.to_wire(), socket.getpeername())
    r, _ = dns.query.receive_udp(socket, socket.getpeername())
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
                return next(iter(d.items()))


def _guess_next_domain(d, key):
    for k, v in d.items():
        if k > key:
            return v


def walk_nsec3(raindict, origin="sk"):
    resolver = dns.resolver.Resolver()
    resolver.use_edns(0, 0, 1200)  # Workaround dnspython bug #546
    nsset = resolver.resolve(f"{origin}.", dns.rdatatype.NS, search=False)
    nsec3cache = dict()
    secureddomains = set()
    secureddomains2 = set()
    originhash = get_nsec3_hash(origin)
    d = origin
    h = originhash
    print("Walking NSEC3 hashes…")
    print(
        ".=indirect discovery d=direct discovery "
        "u=unknown domain discovered\n",
    )
    iters, reqs, brokes, unknowns = 0, 0, 0, 0
    for retries in range(10):
        try:
            nameserver = random.choice(
                [ns.target.to_text() for ns in nsset.rrset],
            )
            print("Using nameserver", nameserver)
            with dns_socket(nameserver) as s:
                while iters == 0 or (h != originhash and d != origin):
                    # print(f"i: {iters:6} q: {reqs:5} h: {h} d: {d}")
                    iters += 1
                    if h not in nsec3cache:
                        # print("Querying", d)
                        q = dns.message.make_query(
                            f"{d}.", "DS", want_dnssec=True,
                        )
                        res = udp_query(s, q)
                        reqs += 1
                        ns3rr = [
                            (
                                rrset.name.labels[0].decode("ascii",).upper(),
                                rrset[0],
                            )
                            for rrset in res.authority
                            if rrset.rdtype == dns.rdatatype.NSEC3
                        ]
                        nsec3cache.update(ns3rr)
                        if [
                            rrset
                            for rrset in res.answer
                            if rrset.rdtype == dns.rdatatype.DS
                        ]:
                            # print(d, "discovered directly")
                            print("d", end="", flush=True)
                            if d in secureddomains2:
                                sys.exit("Cycle detected!")
                            secureddomains2.add(d)
                            h = get_nsec3_hash(d)
                            _, d = _next_odict_item(raindict, h)
                            continue
                        if h not in nsec3cache and len(ns3rr) > 0:
                            newh = min([k for k, v in ns3rr if k > h])
                            print(
                                "\nBroken NSEC3 chain: "
                                "expected", h, "got", newh,
                            )
                            brokes += 1
                            h = newh

                    if dict(nsec3cache[h].windows)[0][5] & 0x10:
                        # this owner has a DS record
                        if h in raindict:
                            d = raindict[h]
                            print(".", end="", flush=True)
                        else:
                            d = f"UNKNOWN_{h}"
                            unknowns += 1
                            print("u", end="", flush=True)
                        # print(d, flush=True)
                        if d in secureddomains:
                            sys.exit("Cycle detected!")
                        secureddomains.add(d)
                    h = digest_to_ascii(nsec3cache[h].next)
                    if h in raindict:
                        _, d = _next_odict_item(raindict, h)
                        if d == origin:
                            # Hack for corner case when
                            # last domain in chain is signed.
                            d = raindict[h]
                    else:
                        print("\nHash not in rainbow table:", h)
                        d = _guess_next_domain(raindict, h)
                        print("Next domain guessed:", d)

        except (EOFError, ConnectionError):
            # Retry in case of server closing TCP connection
            print("\nConnection lost, reconnecting…", flush=True)
        else:  # No exception, work is done
            break
    else:
        raise RuntimeError("Too many retries. Giving up.")

    indirectonly = secureddomains - secureddomains2
    directonly = secureddomains2 - secureddomains
    indirectanddirect = secureddomains & secureddomains2
    secureddomains = secureddomains.union(secureddomains2)
    print("\nIterations: ", iters)
    print("DNS requests: ", reqs)
    print("DS records discovered: ", len(secureddomains))
    print(
        f"{len(indirectonly)} discovered only indirectly, "
        f"{len(directonly)} only directly, "
        f"{len(indirectanddirect)} both ways.",
    )
    print("Unknown domain names: ", unknowns)
    print("Broken NSEC3 chain incidents: ", brokes)
    print("TCP connection retries: ", retries)
    with open("domains-secured.txt", "w") as outf:
        for d in sorted(secureddomains):
            outf.write(d)
            outf.write("\n")
    print(f"Walking {len(nsec3cache)} NSEC3 cache records…")
    # print("\n".join((f"{k} {digest_to_ascii(v.next)}"
    #       for k, v in nsec3cache.items())))
    i1, i2 = tee(sorted(nsec3cache))
    brokes = 0
    for h1, h2 in zip_longest(i1, i2, fillvalue=next(i2)):
        h1next = digest_to_ascii(nsec3cache[h1].next)
        if h1next != h2:
            # print(f"Broken chain, {h1next} expected, {h2} found.")
            brokes += 1
    print(f"Finished. {brokes} incidents found.")
    return secureddomains


def main():
    update_domains_txt()
    raindict = update_rainbow_dict()
    secured = walk_nsec3(raindict)
    write_secured_csv(secured)
    generate_stats(secured)


if __name__ == "__main__":
    main()
