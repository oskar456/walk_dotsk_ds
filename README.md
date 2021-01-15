DNSSEC-enabled domains counter for .SK TLD
==========================================

![Walk NSEC chain](https://github.com/oskar456/walk_dotsk_ds/workflows/Walk%20NSEC%20chain/badge.svg)

This script discovers which domain names in .SK TLD are secured by DNSSEC.
Discovery is done in an efficient way by following the NSEC3 chain, as the
opt-out flag is used and only secured zones have an NSEC3 record.

The script is run daily by Travis CI, results are published in the
[`gh-pages`](https://github.com/oskar456/walk_dotsk_ds/tree/gh-pages) branch and
(hopefully soon) also on [GitHub
pages](https://oskar456.github.io/walk_dotsk_ds/).
