---
title: Deprecating RADIUS/UDP and RADIUS/TCP
abbrev: Deprecating RADIUS
docname: draft-dekok-radext-deprecating-radius-00

stand_alone: true
ipr: trust200902
area: Internet
wg: anima Working Group
kw: Internet-Draft
cat: std
submissionType: IETF

pi:    # can use array (if all yes) or hash here
  toc: yes
  sortrefs:   # defaults to yes
  symrefs: yes

author:

- ins: A. Dekok
  name: Alan DeKok
  org: FreeRADIUS
  email: aland@freeradius.org

normative:
  BCP14: RFC8174
  RFC2865:
  RFC6421:

informative:
  RFC1321:
  RFC5176:
  RFC5580:
  RFC6151:
  RFC6613:
  RFC6614:
  RFC6973:
  RFC7360:

venue:
  group: radext
  mail: radext@ietf.org
  github: freeradius/deprecating-radius.git

--- abstract

This document formally deprecates the use of the User Datagram Protocol (UDP) and of the Transport Congestion Protocol (TCP) as permitted transports for RADIUS (RFC 2865 and RFC 6613).  When using those transports, RADIUS relies on MD5 (RFC 1321) for security, and as a result does not support modern cryptographic algorithms and mechanisms.  Those RADIUS transports do not offer adequate privacy, as the contents of packets are sent "in the clear" or are at best obfuscated with dubious methods which also rely on MD5.

The use of insecure transport has negative implications for privacy and security.  This document deprecates RADIUS/UDP and RADIUS/TCP outside of secure networks.  It mandates the use of TLS-based transports such as RADIUS/TLS and RADIUS/DTLS when RADIUS packets aare sent outside of secure networks.

--- middle

# Introduction

The RADIUS protocol [RFC2865] was first standardized in 1997, though its roots go back much earlier to 1993.  The protocol uses MD5 [RFC1321] to sign a packets, and to obfsucate certain attributes such as User-Password.  While MD5 has been broken, it is a testament to the design of RADIUS that there have been (as yet) no attacks on RADIUS which are stronger than brute-force.

Most information in RADIUS such as user identifiers is sent in cleartext, with obvious privacy implications.  Only a few attributes are hidden, via obfuscation methods which also rely on MD5.

It is no longer approprate to rely on MD5 for security.  It is no longer appropriate to send private information in clear text.  This document therefore deprecates insecure uses of RADIUS, and mandates the use of secure transport layers such as TLS or DTLS.

# Terminology

{::boilerplate bcp14}

* RADIUS

> The Remote Authentication Dial-In User Service protocol, as defined in [RFC2865], [RFC2865], and [RFC5176] among others.

* RADIUS/UDP

> RADIUS over the User Datagram Protocol as define above.

* RADIUS/TCP

> RADIUS over the Transport Congestion Protocol [RFC6613]

* RADIUS/TLS

> RADIUS over the Transport Layer Security protocol [RFC6614]

* RADIUS/DTLS

> RADIUS over the Datagram Transport Layer Security protocol  [RFC7360]

* TLS

> the Transport Layer Security protocol.  Generally when we refer to TLS in this document, we are referring to RADIUS/TLS and/or RADIUS/DTLS.

# Overview of issues with RADIUS

There are a number of issues with RADIUS.   RADIUS sends most information "in the clear", with obvious privacy implications.

Further. MD5 has been broken [RFC6151], and no protocol should be using it for anything.  Even if MD5 was not broken, computers have gotten substantially faster in the past thirty years.  This speed increase makes it possible for the average hobbyist to perform brute-force attacks on cracking shared secrets.

We address each of these issues in detail below.

## Information is sent in Clear Text

Other than a few attributes such as User-Password, all RADIUS traffic is sent "in the clear".  The resulting traffic has a large number of privacy issues.  We refer to [RFC6973], and specifically to Section 5 of that docuemnt for detailed discussion.  RADIUS is vulnerable to all of the issues raised by [RFC6973].

There are clear privacy and security information with sending user identifiers, and user locations [RFC5580] in clear-text across the Internet.  As such, the use of clear-text protocols across insecure networks is no longer appropriate.

## MD5 has been broken

Attacks on MD5 are summarized in part in [RFC6151]. While there have not been many new attacks in the decade since [RFC6151] was published, that does not mean that further attacks do not exist.  It more likely that no one is looking for new attacks.

It is reasonable to expect that new research can further break MD5, but also that such research may not be publicly available.

## Complexity of cracking RADIUS shared secrets

The cost of cracking a a shared secret can only go down over time as computation becomes cheaper.  At the time of writing this document, an "off the shelf" commodity CPU can hash approximately 100,000K octets per second.  If we limit shared secrets to upper/lowercase letters, numbers, and a few "special" characters, we have 64 possible characters for shared secrets.  Which means that for 8-character passwords, there are 2^48 possible password combinations.

The issue is made worse because of the way MD5 is used in RADIUS.  The attacker does not have to calculate the hash over the entire packet, as that can be precalculated, and cached.  The attacker can simply begin with that precalculated portion, and brute-force only the password.

The result is that using one machine, it takes approximately 32 days to brute-force the entire 8 octet / 64 character password space.  The problem is even worse when graphical processing units (GPUs) are used. A high-end GPU is capable of performing more than 64 billion hashes per second.  (https://gist.github.com/Chick3nman/e4fcee00cb6d82874dace72106d73fef).  At that rate, the entire 8 character space described above can be searched in approximately 90 minutes.

This is an attack which is feasible today for a hobbyist. Adding more characters to the permitted character set increases the cost of cracking, but not enough to be secure.

For example, we could extend the character set to 72 characters (uppercase, lowercase, numbers, and 10 "special" characters), and password length to 10 characters.  This change would only increase the cost for a hobbyist from ninety minutes to a bit under two years.

The brute-force attack is also trivially parallelizable.  Nation-states have sufficient resources to deploy hundreds to thousands of systems dedicated to these attacks.

Whether the above numbers are exactly correct, or only approximate is immaterial.  These attacks will only get better over time.  The cost to crack shared secrets will only go down.

Despite the ease of attacking MD5, it is still a common practice for some "cloud" and other RADIUS providers to send RADIUS/UDP packets over the Internet "in the clear".  It is also common practice for administrators to use "short" shared secrets, and to use shared secrets from a limited character set.  Theses practice are followed for ease of use of administrators, but they are also insecure.

Unless RADIUS packets are sent over a secure network (IPSec, TLS, etc.), administrators should assume that any shared secret of 8 characters or less has been immediately compromised.  Administrators should assume that any shared secret of 10 characters or less has been compromised by an attacker with significant resources.  Administrators should also assume that any private information (such as User-Password) which depends on such shared secrets has also been compromised.

In short, if you have sent a User-Password via RADIUS/UDP over the Internet in the last decade, it is very likely that the password is available to an attacker with sufficient resources.

# Deprecating RADIUS, and mandating TLS.

The solution to an insecure protocol using thirty year-old cryptography is to deprecate the insecure cryptography, and to mandate modern cryptographic transport.

## Deprecating UDP and TCP as transports

RADIUS/UDP and RADIUS/TCP MUST NOT be used outside of secure networks.  A secure network is one which is known to be safe from eavesdroppers, attackers, etc.

For example, if IPSec is used between two systems, then those systems may use RADIUS/UDP or RADIUS/TCP over the IPSec connection.

Similarly, RADIUS/UDP and RADIUS/TCP may be used in secure management networks.

However, using RADIUS/UDP and RADIUS/TCP in any environment is still NOT RECOMMENDED.  A network misconfiguration could result in the RADIUS traffic being sent over an insecure network.  Neither the RADIUS client nor the RADIUS server would be aware of this misconfiguration.

In contrast, when TLS is used, the RADIUS endpoints can enforce security themselves.

## Mandating TLS transport

All new RADIUS systems MUST support RADIUS/TLS and/or RADIUS/DTLS.

## Crypto-Agility

The crypto-agility requirements of [RFC6421] are addressed in [RFC6614] Appendix C, and in Section 10.1 of [RFC7360].  For clarity, we repeat the text of [RFC7360] here, with some minor modificiations.

Section 4.2 of [RFC6421] makes a number of recommendations about security properties of new RADIUS proposals.  All of those recommendations are satisfied by using TLS or DTLS as the transport layer.

Section 4.3 of [RFC6421] makes a number of recommendations about backwards compatibility with RADIUS.  [RFC7360] Section 3 addresses these concerns in detail.

Section 4.4 of [RFC6421] recommends that change control be ceded to the IETF, and that interoperability is possible.  Both requirements are satisfied.

Section 4.5 of [RFC6421] requires that the new security methods apply to all packet types.  This requirement is satisfied by allowing TLS and DTLS to be used for all RADIUS traffic.  In addition, [RFC7360] Section 3, addresses concerns about documenting the transition from legacy RADIUS to crypto-agile RADIUS.

Section 4.6 of [RFC6421] requires automated key management.  This requirement is satisfied by using TLS or DTLS key management.

# Migration Path and Recommendations

We recognize that it is difficult to upgrade legacy devices with new cryptographic protocols and user interfaces.  The problem is made worse because the volume of RADIUS devices which are in use.  The exact number is unknown, and can only be approximated.  Our best guesses would be in the order of hundreds of thousands, if not millions.

## Shared Secrets

[RFC2865] Section 3 says:

> It is preferred that the secret be at least 16
> octets.  This is to ensure a sufficiently large range for the
> secret to provide protection against exhaustive search attacks.
> The secret MUST NOT be empty (length 0) since this would allow
> packets to be trivially forged.

This recommendation is no longer adequate, so we strengthen it here.

RADIUS implementations MUST support shared secrets of at least 24 octets, and SHOULD support shared secrets of 64 octets.  Implementations MUST warn administrators that the configured shared secret is insecure if it is 10 octets or less in length.

Administrators SHOULD generate shared secrets from a source of secure random numbers.  Any other practice is likely to lead to compromise of the shared secret.  One solution is to use a simple script (given below)

> \#!/usr/bin/env perl
> use MIME::Base32;
> use Crypt::URandom();
> print join('-', unpack("(A4)*", lc encode_base32(Crypt::URandom::urandom(12)))), "\n";

This script will generate secrets of the form "2nw2-4cfi-nicw-3g2i-5vxq".  This form of secret will be accepted by any known implementation which supports at least 24 octets for shared secrets.  The secrets have 96 bits of entropy, which is adequate for the forseeable future.

Given the simplicity of creating strong secrets, there is no excuse for using weak shared secrets with RADIUS.

## TLS-PSK

We recognize that it may be difficult to fully upgrade client implementations to allow for certificates to be used with RADIUS/TLS and RADIUS/DTLS.  It is therefore RECOMMENDED that client implementations allow the use of a pre-shared key (TLS-PSK).  The client implementation can then expose a flag "TLS yes / no", and then a shared secret (now PSK) entry field.  Any shared secret used for RADIUS/UDP MUST NOT be used for TLS-PSK.

Implementations MUST support PSKs of at least 24 octets, and SHOULD support PSKs of 64 octets.  Implementations MUST require that PSKs be at least 8 octets in length.  That is, short PSKs MUST NOT be permitted to be used.

We also incorporate by reference the requirements of Section 10.2 of [RFC7360] when using PSKs.

# Privacy Considerations

The primary focus of this document is addressing privacy considerations for RADIUS.

Deprecating insecure transport for RADIUS, and requiring secure transport means that personally identifying information is no longer sent "in the clear".  As noted earlier in this document, such information can include MAC addresses, user identifiers, and user locations.

# Security Considerations

The primary focus of this document is addressing security considerations for RADIUS.

Deprecating insecure transport for RADIUS, and requiring secure transport means that historical and/or future security issues with the RADIUS protocol no longer apply.

# IANA Considerations

There are no IANA considerations in this document.

RFC Editor: This section may be removed before final publication.

# Acknowledgements

TBD.

# Changelog


--- back

