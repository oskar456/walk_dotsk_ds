DNSSEC-enabled domains counter for .SK TLD
==========================================

This script discovers, which domain names in .SK TLD are secured by DNSSEC.
Discovery is done in an efficient way by following the NSEC3 chain, as the
opt-out flag is used and only secured zones have an NSEC3 record.
