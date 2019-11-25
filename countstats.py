#!/usr/bin/env python3

import csv
import glob
import datetime
import re
import json
from collections import defaultdict


def getstats():
    datestats = defaultdict(dict)
    for f in glob.glob("gh-pages/20*/domains-stats.csv"):
        date = datetime.date(*[int(x) for x in re.match(
            r"gh-pages/(?P<y>20[0-9]{2})-(?P<m>[0-9]{2})-(?P<d>[0-9]{2})", f,
        ).groups()])
        with open(f, newline='') as inf:
            reader = csv.DictReader(inf)
            for r in reader:
                datestats[date][r['ID reg']] = int(
                    r['secure domains'] if 'secure domains' in r
                    else r['count'],
                )
    return datestats


def crushstats(stats, topn=10):
    topregs = defaultdict(int)
    for s in stats.values():
        for k, v in s.items():
            topregs[k] += v

    topregs = sorted(topregs.items(), key=lambda x: x[1], reverse=True)
    topten = [k for k, v in topregs[1:1+topn]]

    crushedstats = defaultdict(lambda: defaultdict(int))
    for date, s in sorted(stats.items()):
        for reg, count in s.items():
            if reg in topten:
                crushedstats[date][reg] = count
            elif reg == "TOTAL":
                pass
            else:
                crushedstats[date]["OTHERS"] += count

    return crushedstats, topten


def tochartsJSON(crushed, topten):
    output = {
        "rows": [],
        "cols": [
            {
                "label": "date",
                "id": "date",
                "type": "date",
            },
        ],
    }
    for regid in topten:
        output["cols"].append(dict(label=regid, id=regid, type="number"))
    output["cols"].append(dict(label="OTHERS", id="OTHERS", type="number"))
    for k, v in crushed.items():
        output["rows"].append(dict(c=[
            dict(v=f"Date({k.year}, {k.month - 1}, {k.day})"),
            *(dict(v=v[x]) for x in topten),
            dict(v=v["OTHERS"]),
        ]))
    with open("daystats_gchart.json", "w") as outf:
        json.dump(output, outf)


def main():
    stats = getstats()
    crushed, topten = crushstats(stats, 5)
    tochartsJSON(crushed, topten)
    fieldnames = ["date", *topten, "OTHERS"]
    with open("daystats.csv", "w", newline='') as outf:
        writer = csv.DictWriter(outf, fieldnames)
        writer.writeheader()
        for k, v in crushed.items():
            writer.writerow(dict(date=k, **v))


if __name__ == '__main__':
    main()
