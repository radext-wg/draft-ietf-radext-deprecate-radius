# Deprecate RADIUS/UDP and RADIUS/TCP

This document deprecates RADIUS/UDP and RADIUS/TCP.

This document is for the IETF RADEXT WG
http://datatracker.ietf.org/wg/radext

## Security of RADIUS

Unless RADIUS packets are sent over a secure network (IPSec, TLS, etc.), administrators should assume that any shared secret of 8 characters or less has been immediately compromised.  Administrators should assume that any shared secret of 10 characters or less has been compromised by an attacker with significant resources.  Administrators should also assume that any private information (such as User-Password) which depends on such shared secrets has also been compromised.
