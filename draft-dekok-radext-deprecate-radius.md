---
title: Deprecating RADIUS/UDP and RADIUS/TCP
abbrev: Deprecating RADIUS
docname: draft-dekok-radext-deprecating-radius-04

stand_alone: true
ipr: trust200902
area: Internet
wg: RADEXT Working Group
kw: Internet-Draft
cat: std
submissionType: IETF

pi:    # can use array (if all yes) or hash here
  toc: yes
  sortrefs:   # defaults to yes
  symrefs: yes

author:

- ins: A. DeKok
  name: Alan DeKok
  org: FreeRADIUS
  email: aland@freeradius.org

normative:
  BCP14: RFC8174
  RFC2865:
  RFC6421:
  RFC8044:

informative:
  RFC1321:
  RFC2866:
  RFC2868:
  RFC3579:
  RFC5176:
  RFC5580:
  RFC6151:
  RFC6218:
  RFC6613:
  RFC6614:
  RFC6973:
  RFC7360:
  I-D.dekok-radext-tls-psk:
  I-D.tomas-openroaming:
  I-D.josefsson-pppext-eap-tls-eap:
  EDUROAM:
     title: "eduroam"
     author:
       name: eduroam
     format:
       TXT:  https://eduroam.org
  OPENROAMING:
     title: "OpenRoaming: One global Wi-Fi network"
     author:
       name: Wireless Broadband Alliance
     format:
       TXT:  https://wballiance.com/openroaming/
  WIFILOC:
     title: "Accurate indoor location with Wi-Fi connectivity"
     author:
       name: "Wi-Fi Alliance"
     format:
       TXT: https://www.wi-fi.org/discover-wi-fi/wi-fi-location

venue:
  group: RADEXT
  mail: radext@ietf.org
  github: freeradius/deprecating-radius.git

--- abstract

RADIUS crypto-agility was first mandated as future work by RFC 6421.  The outcome of that work was the publication of RADIUS over TLS (RFC 6614) and RADIUS over DTLS (RFC 7360) as experimental documents.  Those transport protocols have been in wide-spread use for many years in a wide range of networks.  They have proven their utility as replacements for the previous UDP (RFC 2865) and TCP (RFC 6613) transports.  With that knowledge, the continued use of insecure transports for RADIUS has serious and negative implications for privacy and security.

This document formally deprecates the use of the User Datagram Protocol (UDP) and of the Transmission Control Protocol (TCP) as transport protocols for RADIUS. These transports are permitted inside of secure networks, but their use even in that environment is strongly discouraged.  For all other environments, the use of secure transports such as IPsec or TLS is mandated.

--- middle

# Introduction

The RADIUS protocol {{RFC2865}} was first standardized in 1997, though its roots go back much earlier to 1993.  The protocol uses MD5 {{RFC1321}} to sign some packets types, and to obfuscate certain attributes such as User-Password.  As originally designed, Access-Request packets were entirely unauthenticated, and could be trivially spoofed as discussed in {{RFC3579}} Section 4.3.2.  In order to prevent such spoofing, that specification defined the Message-Authenticator attribute ({{RFC3579}} Section 3.2) which allowed for packets to carry a signature based on HMAC-MD5.

The state of MD5 security was discussed in {{RFC6151}}, which led to the state of RADIUS security being reviewed in {{RFC6421}} Section 3.  The outcome of that review was the remainder of {{RFC6421}}, which created crypto-agility requirements for RADIUS.

RADIUS was traditionally secured with IPSec, as described in {{RFC3579}} Section 4.2:

> To address the security vulnerabilities of RADIUS/EAP,
> implementations of this specification SHOULD support IPsec
> (RFC2401) along with IKE (RFC2409) for key management.  IPsec ESP
> (RFC2406) with non-null transform SHOULD be supported, and IPsec
> ESP with a non-null encryption transform and authentication
> support SHOULD be used to provide per-packet confidentiality,
> authentication, integrity and replay protection.  IKE SHOULD be
used for key management.

The use of IPSec allowed RADIUS to be sent privately, and securely, across the Internet.  However, experience showed that TLS was in many ways simpler (implementation and deployment) than IPSec.

RADIUS/TLS {{RFC6614}} and RADIUS/DTLS {{RFC7360}} were then defined in order to meet the crypto-agility requirements of {{RFC6421}}.  RADIUS/TLS has been in wide-spread use for about a decade, including eduroam {{EDUROAM}}, and more recently OpenRoaming {{OPENROAMING}} and {{I-D.tomas-openroaming}}.  RADIUS/DTLS has seen less use across the public Internet, but it nonetheless has multiple implementations.

As of the writing of this specification, RADIUS/UDP is still widely used, even though it depends on MD5 and "ad hoc" constructions for security.  While MD5 has been broken, it is a testament to the design of RADIUS that there have been (as yet) no attacks on RADIUS Authenticator signatures which are stronger than brute-force.

However, the problems with MD5 means that if a someone can view unencrypted RADIUS traffic, even a hobbyist attacker can crack all possible RADIUS shared secrets of eight characters or less.  Such attacks can also result in compromise of all passwords carried in the User-Password attribute.

Even if a stronger packet signature method was used as in {{RFC6218}}, it would not fully address the issues with RADIUS.  Most information in RADIUS is sent in clear-text, and only a few attributes are hidden via obfuscation methods which rely on more "ad hoc" MD5 constructions.  The privacy implications of this openness are severe.

Any observer of non-TLS RADIUS traffic is able to obtain a substantial amount of personal identifiable information (PII) about users.  The observer can tell who is logging in to the network, what devices they are using, where they are logging in from, and their approximate location (usually city).  With location-based attributes as defined in {{RFC5580}}, a users location may be determined to within 15 or so meters outdoors, and with "meter-level accuracy indoors" {{WIFILOC}}.  An observer can also use RADIUS accounting packets to determine how long a user is online, and to track a summary of their total traffic (upload and download totals).

When RADIUS/UDP is used across the public Internet, the location of individuals can potentially be tracked in real-time (usually 10 minute intervals), to within 15 meters.  Their devices can be identified, and tracked.  Any passwords they send via the User-Password attribute can be be compromised.  The implications for security and individual safety are large, and negative.

These issues are only partly mitigated when the attributes carried within RADIUS define their own methods to increase security and privacy.  For example, some authentication methods such EAP-TLS, EAP-TTLS, etc. allow for User-Name privacy and for more secure transport of passwords.  The use of MAC address randomization can limit device information identification to a particular manufacturer, instead of to a unique device.

However, these authentication methods are not always used or are not always available.  Even if these methods were used ubiquitously, they do not protect all of the information which is publicly available when RADIUS/UDP or RADIUS/TCP is used.

It is no longer acceptable for RADIUS to rely on MD5 for security.  It is no longer acceptable to send device or location information in clear text.  This document therefore deprecates insecure uses of RADIUS, and mandates the use of secure TLS-based transport layers.

The use of a secure transport such as IPSec or TLS ensures complete privacy and security for all RADIUS traffic.  An observer is limited to knowing rough activity levels of a client or server.  That is, an observer can tell if there are a few users on a NAS, or many users on a NAS.  All other information is hidden from all observers.

It is also possible for an attacker to record the session traffic, and later crack the TLS session key.  This attack could comprise all traffic sent over that connection, including EAP session keys.  If the cryptographic methods provide forward secrecy ({{?RFC7525}} Section 6.3), then breaking one session provides no information about other sessions.  As such, it is RECOMMENDED that all cryptographic methods used to secure RADIUS conversations provide forward secrecy.  While forward secrecy will not protect individual sessions from attack, it will prevent attack on one session from being leveraged to attack other, unrelated, sessions.

AAA servers should minimize the impact of such attacks by using a total throughput (recommended) or time based limit before replacing the session keys.  The session keys can be replaced though a process of either rekeying the existing connection, or by opening a new connection and deprecating the use of the original connection.  If the original connection if closed before a new connection is open, it can cause spurious errors in a proxy environment.

The final attack possible in a AAA system is where one party in a AAA conversation is compromised or run by a malicious party.  This attack is made more likely by the extensive use of RADIUS proxy forwarding chains.  In that situation, every RADIUS proxy has full visibility into, and control over, the traffic it transports.  The solution here is to minimize the number of proxies involved, such as by using Dynamic Peer Discovery ({{?RFC7585}}.

## Overview

The rest of this document begins a summary of issues with RADIUS, and shows just how trivial it is to crack RADIUS/UDP security.  We then mandate the use of secure transport, and describe what that means.  We give recommendations on how current systems can be migrated to using TLS.  We conclude with privacy and security considerations.

As IPSec has been discussed previously in the context of RADIUS, we devote little time to it here, other than to say it is an acceptable solution.  As the bulk of the current efforts are focused on TLS, this document likewise focuses on TLS.

While this document tries to be comprehensive, it is necessarily imperfect.  There may be issues which should have been included, but which were missed due to oversight or accident.  Any reader should be aware that there are good practices which are perhaps not documented here.  We recommend following reasonable practices, even if those practices are not written down in a public specification.

There is a common tendency to suggest that a particular practice is "allowed" by a specification, simply because the specification does not forbid that practice.  This belief is wrong.  By their very nature, documents include a small number of permitted, required, and/or forbidden behaviors.  There are a much larger set of behaviors which are undefined.  That is, behaviors which are neither permitted nor forbidden.  Those behaviors may be good or bad, independent of what the specification says.

Outside of specificaitons, there is also a large set of common practices and behaviors which have grown organically over time, but which have not been written into a specification.  These practices have been found to be valuable by implementors and administrators.  Deviations from these practices generally result in instabilities and incompatibilities between systems.  As a result, implementors should exercise caution when creating new behaviors which have not previously been seen in the space.  Such behaviors are likely to be wrong.

# Terminology

{::boilerplate bcp14}

* RADIUS

> The Remote Authentication Dial-In User Service protocol, as defined in {{RFC2865}}, {{RFC2865}}, and {{RFC5176}} among others.

* RADIUS/UDP

> RADIUS over the User Datagram Protocol as define above.

* RADIUS/TCP

> RADIUS over the Transport Control Protocol {{RFC6613}}

* RADIUS/TLS

> RADIUS over the Transport Layer Security protocol {{RFC6614}}

* RADIUS/DTLS

> RADIUS over the Datagram Transport Layer Security protocol  {{RFC7360}}

* TLS

> the Transport Layer Security protocol.  Generally when we refer to TLS in this document, we are referring to RADIUS/TLS and/or RADIUS/DTLS.

* NAS

> Network Access Server, which is a RADIUS client.

# Overview of issues with RADIUS

There are a number of issues with RADIUS.   For one, RADIUS sends most information "in the clear", with obvious privacy implications.

Further, MD5 has been broken for over a decade, as summarized in {{RFC6151}}.  No protocol should be using MD5 for anything.  Even if MD5 was not broken, computers have gotten substantially faster in the past thirty years.  This speed increase makes it possible for the average hobbyist to perform brute-force attacks to crack even seemingly complex shared secrets.

We address each of these issues in detail below.

## Information is sent in Clear Text

Other than a few attributes such as User-Password, all RADIUS traffic is sent "in the clear".  The resulting traffic has a large number of privacy issues.  We refer to {{RFC6973}}, and specifically to Section 5 of that document for detailed discussion.  RADIUS is vulnerable to all of the issues raised by {{RFC6973}}.

There are clear privacy and security information with sending user identifiers, and user locations {{RFC5580}} in clear-text across the Internet.  As such, the use of clear-text protocols across insecure networks is no longer acceptable.

## MD5 has been broken

Attacks on MD5 are summarized in part in {{RFC6151}}. While there have not been many new attacks in the decade since {{RFC6151}} was published, that does not mean that further attacks do not exist.  It is more likely that no one is looking for new attacks.

It is reasonable to expect that new research can further break MD5, but also that such research may not be publicly available.

## Complexity of cracking RADIUS shared secrets

The cost of cracking a a shared secret can only go down over time as computation becomes cheaper.  The issue is made worse because of the way MD5 is used in RADIUS.  The attacker does not have to calculate the hash over the entire packet, as that can be precalculated, and cached.  The attacker can simply begin with that precalculated portion, and brute-force only the shared secret portion.

At the time of writing this document, an "off the shelf" commodity computer can calculate at least 100M MD5 hashes per second.  If we limit shared secrets to upper/lowercase letters, numbers, and a few "special" characters, we have 64 possible characters for shared secrets.  Which means that for 8-character passwords, there are 2^48 possible password combinations.

The result is that using one readily available machine, it takes approximately 32 days to brute-force the entire 8 octet / 64 character password space.  The problem is even worse when graphical processing units (GPUs) are used. A high-end GPU is capable of performing more than 64 billion hashes per second.  At that rate, the entire 8 character space described above can be searched in approximately 90 minutes.

This is an attack which is feasible today for a hobbyist. Increasing the size of the character set raises the cost of cracking, but not enough to be secure.  Increasing the character set to 93 characters means that the hobbyist using a GPU could search the entire 8 character space in about a day.

Increasing the length of the shared secret a bit helps.  For secrets ten characters long, a GPU can search a 64-character space in about six months, and a 93 character space would take approximately 24 years.

The brute-force attack is also trivially parallelizable.  Nation-states have sufficient resources to deploy hundreds to thousands of systems dedicated to these attacks.  That realization means that a "time to crack" of 24 years is simply expensive, but is not particularly difficult.

Whether the above numbers are exactly correct, or only approximate is immaterial.  These attacks will only get better over time.  The cost to crack shared secrets will only go down.

Even worse, administrators do not always derive shared secrets from secure sources of random numbers.  The "time to crack" numbers given above are the absolute best case, assuming administrators follow best practices for creating secure shared secrets.  For shared secrets created manually by a person, the search space is orders of magnitude smaller than the best case outlined above.

It should be assumed that an average attacker with modest resource can crack most human-derived shared secrets in minutes, if not seconds.

Despite the ease of attacking MD5, it is still a common practice for some "cloud" and other RADIUS providers to send RADIUS/UDP packets over the Internet "in the clear".  It is also common practice for administrators to use "short" shared secrets, and to use shared secrets created by a person, or derived from a limited character set.  Theses practice are followed for ease of use of administrators, but they are also highly insecure.

## Tunnel-Password and CoA-Request packets

There are similar security issues for the Tunnel-Password attribute, at least in CoA-Request and Disconnect-Request packets.

{{RFC5176}} Section 2.3 says:

    Request Authenticator

       In Request packets, the Authenticator value is a 16-octet MD5
       [RFC1321] checksum, called the Request Authenticator.  The
       Request Authenticator is calculated the same way as for an
       Accounting-Request, specified in [RFC2866].

Where {{RFC2866}} Section 3 says:

      The NAS and RADIUS accounting server share a secret.  The Request
      Authenticator field in Accounting-Request packets contains a one-
      way MD5 hash calculated over a stream of octets consisting of the
      Code + Identifier + Length + 16 zero octets + request attributes +
      shared secret (where + indicates concatenation).  The 16 octet MD5
      hash value is stored in the Authenticator field of the
      Accounting-Request packet.

Taken together, these definitions means that for CoA-Request packets, all attribute obfuscation is calculated with the Reply Authenticator being all zeroes.

{{RFC5176}} Section 3.6 allows for Tunnel-Password in CoA-Request packets:

      ...
      Change-of-Authorization Messages
      
      Request   ACK      NAK   #   Attribute
      ...
      0+        0        0    69   Tunnel-Password (Note 5)
      ...
      (Note 5) When included within a CoA-Request, these attributes
      represent an authorization change request.  Where tunnel attributes
      are included within a successful CoA-Request, all existing tunnel
      attributes are removed and replaced by the new attribute(s).

However, {{RFC2868}} Section 3.5 says that Tunnel-Password is encrypted with the Request Authenticator:

      Call the shared secret S, the pseudo-random 128-bit Request
      Authenticator (from the corresponding Access-Request packet) R,

The assumption that the Request Authenticator is random data is true for Access-Request packets.  It is not true for CoA-Request packets

That is, when the Tunnel-Password attribute is used in CoA-Request packets, the only source of randomness in the obfuscation is the salt, as defined in {{RFC2868}} Section 3.5;

    Salt
      The Salt field is two octets in length and is used to ensure the
      uniqueness of the encryption key used to encrypt each instance of
      the Tunnel-Password attribute occurring in a given Access-Accept
      packet.  The most significant bit (leftmost) of the Salt field
      MUST be set (1).  The contents of each Salt field in a given
      Access-Accept packet MUST be unique.
 
Which means that there is only 15 bits of entropy in the Tunnel-Password obfuscation (plus the secret).  It is not known if this limitation makes it easier to determine the contents of the Tunnel-Password.  However, it cannot be a good thing, and it is one more reason to deprecate RADIUS/UDP.

# All short Shared Secrets have been compromised

Unless RADIUS packets are sent over a secure network (IPsec, TLS, etc.), administrators should assume that any shared secret of 8 characters or less has been immediately compromised.  Administrators should assume that any shared secret of 10 characters or less has been compromised by an attacker with significant resources.  Administrators should also assume that any private information (such as User-Password) which depends on such shared secrets has also been compromised.

Further, if a User-Password has been sent over the Internet via RADIUS/UDP or RADIUS/TCP in the last decade, you should assume that password has been compromised by an attacker with sufficient resources.

# Deprecating Insecure transports

The solution to an insecure protocol using thirty year-old cryptography is to deprecate the insecure cryptography, and to mandate modern cryptographic transport.

## Deprecating UDP and TCP as transports

RADIUS/UDP and RADIUS/TCP MUST NOT be used outside of secure networks.  A secure network is one which is known to be safe from eavesdroppers, attackers, etc.

For example, if IPsec is used between two systems, then those systems may use RADIUS/UDP or RADIUS/TCP over the IPsec connection.

Similarly, RADIUS/UDP and RADIUS/TCP may be used in secure management networks.  However, administrators should not assume that such uses are secure.

Using RADIUS/UDP and RADIUS/TCP in any environment is still NOT RECOMMENDED.  A network misconfiguration could result in the RADIUS traffic being sent over an insecure network.  Neither the RADIUS client nor the RADIUS server would be aware of this misconfiguration.

In contrast, when TLS is used, the RADIUS endpoints are aware of all security issues, and can enforce security for themselves.

### Message-Authenticator

The Message-Authenticator attribute was defined in {{RFC3579}} Section 3.2.  The "Note 1" paragraph at the bottom of {{RFC3579}} Section 3.2 required that Message-Authenticator be added to Access-Request packets when the EAP-Message as present, and suggested that it should be present in a few other situations.   Experience has shown that these recommendations are inadequate.

Some RADIUS clients never use the Message-Authenticator attribute, even for the situations where it the {{RFC3579}} text suggests that it should be used.  When the Message-Authenticator attribute is missing from Access-Request packets, it is often possible to trivially forge or replay those packets.

For example, an Access-Request packet containing CHAP-Password but which is missing Message-Authenticator can be trivially forged.  If an attacker sees one packet such packet, it is possible to replace the CHAP-Password and CHAP-Challenge (or Request Authenticator) with values chosen by the attacker.  The attacker can then perform brute-force attacks on the RADIUS server in order to test passwords.  Similar attacks are possible for User-Password and MS-CHAP passwords.

This document therefore requires that RADIUS clients MUST include the Message-Authenticator in all Access-Request packets when UDP or TCP transport is used.  In contrast, when TLS-based transports are used, the Message-Authenticator attribute serves no purpose, and can be omitted, even when the Access-Request packet contains an EAP-Message attribute.  Servers receiving Access-Request packets over TLS-based transports SHOULD NOT silently discard the packet if it does not contain a Message-Authenticator attribute.  However, if the Message-Authenticator attributes is present, it still MUST be validated as discussed in {{RFC7360}} and {{RFC3579}}.

## Mandating Secure transports

All systems sending RADIUS packets outside of secure networks MUST use either IPSec, RADIUS/TLS, or RADIUS/DTLS. It is RECOMMENDED, for operational and visibility reasons, that RADIUS/TLS or RADIUS/DTLS are preferred over IPSec.

Unlike (D)TLS, use of IPSec means that applications are generally unaware of transport-layer security. Any problem with IPSec such as configuration issues, negotiation or re-keying problems are typically  presented to the RADIUS servers as 100% packet loss.  These issues may occur at any time, independent of any changes to a RADIUS application using that transport.  Further, network misconfigurations which remove all security are completely transparent to the RADIUS application: packets can be sent over an insecure link, and the RADIUS server is unaware of the failure of the security layer.

In contrast, (D)TLS gives the RADIUS application completely knowledge and control over transport-layer security.  The failure cases around (D)TLS are therefore often clearer, easier to diagnose and faster to resolve than failures in IPSec.

## Crypto-Agility

The crypto-agility requirements of {{RFC6421}} are addressed in {{RFC6614}} Appendix C, and in Section 10.1 of {{RFC7360}}.  For clarity, we repeat the text of {{RFC7360}} here, with some minor modifications to update references, but not content.

Section 4.2 of {{RFC6421}} makes a number of recommendations about security properties of new RADIUS proposals.  All of those recommendations are satisfied by using TLS or DTLS as the transport layer.

Section 4.3 of {{RFC6421}} makes a number of recommendations about backwards compatibility with RADIUS.  {{RFC7360}} Section 3 addresses these concerns in detail.

Section 4.4 of {{RFC6421}} recommends that change control be ceded to the IETF, and that interoperability is possible.  Both requirements are satisfied.

Section 4.5 of {{RFC6421}} requires that the new security methods apply to all packet types.  This requirement is satisfied by allowing TLS and DTLS to be used for all RADIUS traffic.  In addition, {{RFC7360}} Section 3, addresses concerns about documenting the transition from legacy RADIUS to crypto-agile RADIUS.

Section 4.6 of {{RFC6421}} requires automated key management.  This requirement is satisfied by using TLS or DTLS key management.

We can now finalize the work began in {{RFC6421}}.  This document updates {{RFC2865}} et al. to state that any new RADIUS specification MUST NOT introduce new "ad hoc" cryptographic primitives to sign packets as with the Response Authenticator, or to obfuscate attributes as was done with User-Password and Tunnel-Password.  That is, RADIUS-specific cryptographic methods existing as of the publication of this document can continue to be used for historical compatibility.  However, all new cryptographic work in the RADIUS protocol is forbidden.

We recognize that RADIUS/UDP will still be in use for many years, and that new standards may require some modicum of privacy.  As a result, it is a difficult choice to forbid the use of these constructs.  If an attack is discovered which breaks RADIUS/UDP (e.g. by allowing attackers to forge Request Authenticators or Response Authenticators, or by allowing attackers to de-obfuscate User-Password), the solution is to simply deprecate the use of RADIUS/UDP entirely.  It would not be acceptable to design new cryptographic primitives which attempt to "secure" RADIUS/UDP.

All new security and privacy requirements in RADIUS MUST be provided by a secure transport layer such as TLS or IPSec.  We note that simply using IPsec is not always enough, as the use (or not) of IPsec is unknown to the RADIUS application.  For example, when the IPsec connection is down, the RADIUS application sees 100% packet loss for no reason which can be determined.  In contrast, a failed TLS connection may return a "connection refused" error to the application, or any one of many TLS errors indicating which exact part of the TLS conversion failed during negotiation.

The restriction forbidding new cryptographic work in RADIUS does not apply to the data being transported in RADIUS attributes.  For example, a new authentication protocol could use new cryptographic methods, and would be permitted to be transported in RADIUS.  In that case, RADIUS serves as a transport layer for the authentication method, which is treated as opaque data for the purposes of Access-Request, Access-Challenge, etc.  There would be no need for RADIUS to define any new cryptographic methods in order to transport this data.  Either the authentication method itself is secured (as with EAP-TLS), or the authentication data can be obfuscated (as with User-Password), or the entire RADIUS exchange can be secured via TLS or IPSec transport.

Similarly, new specifications MAY define new attributes which use the obfuscation methods for User-Password as defined in {{RFC2865}} Section 5.2, or for Tunnel-Password as defined in {{RFC2868}} Section 3.5.  However, due to the issues noted above with the obfuscation method used for Tunnel-Password, that obfuscation method MUST only used for attributes which are sent Access-Request packets.  If the attribute needs to be send in another type of packet, then the protocol design is likely wrong, and needs to be revisited.  It is again a difficult choice to forbid the use of the Tunnel-Password obfuscation method, but we believe that doing so is preferable to allowing "secret" data to be obfuscated with only 15 bits of entropy.

# Migration Path and Recommendations

We recognize that it is difficult to upgrade legacy devices with new cryptographic protocols and user interfaces.  The problem is made worse because the volume of RADIUS devices which are in use.  The exact number is unknown, and can only be approximated.  Our best guesses would be in the order of hundreds of thousands, if not millions of RADIUS/UDP devices are in daily use.

We therefore need to define a migration path to using secure transports.  We give a few migration steps by making stronger recommendations for shared secrets.  Where {{RFC6614}} Section 2.3 makes support for TLS-PSK optional, we suggest that RADIUS/TLS and RADIUS/DTLS implementations SHOULD support TLS-PSK.  Implementation and operational considerations for TLS-PSK are given in {{I-D.dekok-radext-tls-psk}}, and we do not repeat them here.

## Shared Secrets

{{RFC2865}} Section 3 says:

> It is preferred that the secret be at least 16
> octets.  This is to ensure a sufficiently large range for the
> secret to provide protection against exhaustive search attacks.
> The secret MUST NOT be empty (length 0) since this would allow
> packets to be trivially forged.

This recommendation is no longer adequate, so we strengthen it here.

RADIUS implementations MUST support shared secrets of at least 32 octets, and SHOULD support shared secrets of 64 octets.  Implementations MUST warn administrators that the shared secret is insecure if it is 10 octets or less in length.

Administrators SHOULD use shared secrets of at least 24 octets, generated using a source of secure random numbers.   Any other practice is likely to lead to compromise of the shared secret, user information, and possibly of the entire network.

Creating secure shared secrets is not difficult.  One solution is to use a simple script given below.  While the script is not portable to all possible systems, the intent here is to document a concise and simple method for creating secrets which are secure, and humanly manageable.

> \#!/usr/bin/env perl
> use MIME::Base32;
> use Crypt::URandom();
> print join('-', unpack("(A4)*", lc encode_base32(Crypt::URandom::urandom(12)))), "\n";

This script reads 96 bits of random data from a secure source, encodes it in Base32, and then makes it easier for people to work with.  The generated secrets are of the form "2nw2-4cfi-nicw-3g2i-5vxq".  This form of secret will be accepted by any known implementation which supports at least 24 octets for shared secrets.

Given the simplicity of creating strong secrets, there is no excuse for using weak shared secrets with RADIUS.  The management overhead of dealing with complex secrets is less than the management overhead of dealing with compromised networks.

RADIUS implementors SHOULD provide tools for administrators which can create and manage secure shared secrets.

Given the insecurity of RADIUS, the absolute minimum acceptable security is to use strong shared secrets.  However, administrator overhead for TLS-PSK is not substantially higher than simple shared secrets, and TLS-PSK offers significantly increased security and privacy.

# Increasing the Security of RADIUS Transports

While we still permit the use of UDP and TCP transports in secure environments, there remain opportunities for increasing the security of those transport protocols.  The amount of personal identifiable information sent in packets should be minimized.  Information about the size, structure, and nature of the visited network should be omitted or anonymized.  The choice of authentication method also has security and privacy impacts.

The recommendations here for increasing the security of RADIUS transports also applies when TLS is used.  TLS transports protect the RADIUS packets from observation by from third-parties.  However, TLS does not hide the content of RADIUS packets from intermediate proxies, such as in a roaming environment.  As such, the main path to minimizing the information sent to proxies is to minimize the number of proxies involved.

Implementors and administrators need to be aware of all of these issues, and then make the best choice for their local network which balances their requirements on privacy, security, and cost.

## Minimizing Personal Identifiable Information

One approach to increasing RADIUS privacy is to minimize the amount of PII which is sent in packets.  Implementors of RADIUS products and administrators of RADIUS systems SHOULD ensure that only the minimum necessary PII is sent in RADIUS.

Where possible, identities should be anonymized (e.g. {{?RFC7542}} Section 2.4).  The use of anonymized identies means that the the Chargeable-User-Identifer {{?RFC4372}} should also be used.  Further discussion on this topic is below.

Device information SHOULD be either omitted, or randomized.  e.g. MAC address randomization could be used on end-user devices.  The details behind this recommendation are the subject of ongoing research and development.  As such, we do not offer more specific recommendations here.

Information about the visited network SHOULD be replaced or anonymized before packets are proxied outside of the local organization.  The attribute Operator-NAS-Identifier {{?RFC8559}} can be used to anonymize information about NASes in the local network.

Location information ({{RFC5580}} SHOULD either be omitted, or else it SHOULD be limited to the broadest possible information, such as country code. For example, {{I-D.tomas-openroaming}} says:

> All OpenRoaming ANPs MUST support signalling of location information

This location information is required to include at the minimum the country code.  We suggest the country code SHOULD also be the maximum amount of location information which is sent over third-party networks.

### Chargeable-User-Identity

Where the Chargeable-User-Identity (CUI) {{?RFC4372}} is used, it SHOULD be unique per session.  This practice will help to maximize user privacy, as it will be more difficult to track users across multiple sessions.  Due to additional constraints which we will discuss below, we cannot require that the CUI change for every session.

What we can do is to require that the home server MUST provide a unique CUI for each combination of user and visited network.  That is, if the same user visits multiple networks, the home server MUST provide different CUIs to each visited network for that user.  The CUI MAY be the same across multiple sessions for that user on one particular network.  The CUI MAY be the same for multiple devices used by that user on one particular network.

We note that the MAC address is likely the same across multiple user sessions on one network.  Therefore changing the CUI offers little additional benefit, as the user can still be tracked by the unchanging MAC address.  Never the less, we believe that having a unique CUI per session can be useful, because there is ongoing work on increasing user privacy by allowing more MAC address randomization.  If we were to recommend that the CUI remain constant across multiple sessions, that would in turn negate much of the effort being put into MAC address randomization.

One reason to have a constant CUI value for a user (or user devices) on one network is that network access providers may need to enforce limits on simultaneous logins.  Network providers may also need to correlate user behavior across multiple sessions in order to track and prevent abuse.  Both of these requirements are impossible if the CUI changes for every user session.

The result is that there is a trade-off between user privacy and the needs of the local network.  While perfect user privacy is an admirable goal, perfect user privacy may also allow anonymous users to abuse the visited network.  The network would then likely simply refuse to provide network access.  Users may therefore have to accept some limitations on privacy, in order to obtain network access.

We take a short digression here to give some recommendations for creating and managing of CUI.  We believe that these recommendations will help implementors satisfy the preceding requirements, while not imposing undue burden on the implementations.

In general, the simplest way to track CUIs long term is to associate the CUI to user identity in some kind of cache or database.  This association could be created at the tail end of the authentication process, and before any accounting packets were received.  This association should generally be discarded after a period of time if no accounting packets are received.  If accounting packets are received, the CUI to user association should then be tracked along with the normal accounting data.

The above method for tracking CUI works no matter how the CUI is generated.  If the CUI can be unique per session, or it could be tied to a particular user identity across a long period of time.  The same CUI could also be associated with multiple devices.

Where the CUI is not unique for each session, the only minor issue is the cost of the above method is that the association is stored on a per-session basis when there is no need for that to be done.  Storing the CUI per session means that is it possible to arbitrarily change how the CUI is calculated, with no impact on anything else in the system.  Designs such as this which decouple unrelated architectural elements are generally worth the minor extra cost.

For creating the CUI, that process should be done in a way which is scalable and efficient.  For a unique CUI per user, implementors SHOULD create a value which is unique both to the user, and to the visited network.  There is no reason to use the same CUI for multiple visited networks, as that would enable the tracking of a user across multiple networks.

Before suggesting a method for creating the CUI, we note that {{RFC4372}} Section 2.1 defines the CUI as being of data type 'string' ({{RFC8044}} Section 3.5).  {{RFC4372}} Section 2.1 further suggests that the value of the CUI is interpreted as an opaque token, similar to the Class attribute ({{RFC2865}} Section 5.25).  Some organizations create CUI values which use the Network Access Identifier (NAI) format as defined in {{RFC7542}}.  This format can allow the home network to be identified to the visited network, where the User-Name does not contain a realm.  Such formats SHOULD NOT be used unless all parties involved have agreed to this behavior.

The CUI SHOULD be created via a construct similar to what is given below, where "+" indicates concatenation:

~~~~
CUI = HASH(visited network data + user identifier + key)
~~~~

This construct has the following conceptual parameters.

> HASH
>
>> A cryptographic hash function.

> visited network data
>
>> Data which identifies the visited network.
>>
>> This data could be the Operator-Name attribute ({{RFC5580}} Section 4.1).

> user identifier
>
>> The site-local user identifier.  For tunneled EAP methods such as PEAP or TTLS, this could be the user identity which is sent inside of the TLS tunnel.

> key
>
>> A secret known only to the local network.  The key is generally a large random string.  It is used to help prevent dictionary attacks on the CUI.

Where the CUI needs to be constant across multiple user sessions or devices, the key can be a static value.  It is generated once by the home network, and then stored for use in further CUI derivations.

Where the CUI needs to be unique per session, the above derivation SHOULD still be used, except that the "key" value will instead be a random number which is different for each session.  Using such a design again decouples the CUI creation from any requirement that it is unique per session, or constant per user.  That decision can be changed at any time, and the only piece which needs to be updated is the derivation of the "key" field.  In contrast, if the CUI is generated completely randomly per session, then it may be difficult for a system to later change that behavior to allow the CUI to be constant for a particular user.

If an NAI format is desired, the hash output can be converted to printable text, truncated if necessary to meet length limitations, and then an "@" character and a realm can be appended to it.  The resulting text string is then in NAI form.

We note that the above recommendation is not invertible.  That is, given a particular CUI, it is not possible to determine which visited network or user identifier was used to create it.  If it is necessary to use the CUI to determine which user is associated with it, the local network still needs to store the full set of CUI values which are associated with each user.

If this tracking is too complex for a local network, it is possible to create the CUI via an invertible encryption process as follows:

~~~~
CUI = ENCRYPT(key, visited network data + user identifier)
~~~~

This construct has the following conceptual parameters.

> ENCRYPT
>
>> A cryptographically secure encryption function

> key
>
>> The encryption key.  Note that the same key must not be used for more both hashing and encryption.

> visited network data
>
>> Data which identifies the visited network.
>>
>> This data could be the Operator-Name attribute ({{RFC5580}} Section 4.1).

> user identifier
>
>> The site-local user identifier.  For tunneled EAP methods such as PEAP or TTLS, this could be the user identity which is sent inside of the TLS tunnel.

However, the use of a hash-based method is RECOMMENDED.

In short, the intent is for CUI to leak as little information as possible, and ideally be different for every session.  However, business agreements, legal requirements, etc. may mandate different behavior.  The intention of this section is not to mandate complete CUI privacy, but instead to clarify the trade-offs between CUI privacy and business realities.

## User-Password and Proxying

The design of RADIUS means that when proxies receive Access-Request packets, the clear-text contents of the User-Password attribute are visible to the proxy.  Despite various claims to the contrary, the User-Password attribute is never sent "in the clear" over the network.  Instead, the password is protected by TLS (RADIUS/TLS) or via the obfuscation methods defined in {{RFC2865}} Section 5.2.  However, the nature of RADIUS means that each proxy must first undo the password obfuscation of {{RFC2865}}, and then re-do it when sending the outbound packet.  As such, the proxy has the clear-text password visible to it, and stored in its application memory.

It is therefore possible for every intermediate proxy to snoop and record all user identities and passwords which they see.  This exposure is most problematic when the proxies are administered by an organization other than the one which operates the home server.  Even when all of the proxies are operated by the same organization, the existence of clear-text passwords on multiple machines is a security risk.

It is therefore NOT RECOMMENDED for organizations to send User-Password attributes in packets which are sent outside of the local organization.  If RADIUS proxying is necessary, another authentication method SHOULD be used.

Client and server implementations SHOULD use programming techniques to securely wipe passwords from memory when they are no longer needed.

Organizations MAY still use User-Password attributes within their own systems, for reasons which we will explain in the next section.

## PAP vs CHAP vs MS-CHAP, etc.

Some organizations may desire to increase the security of their network by using alternate authentication methods such as CHAP or MS-CHAP, instead of PAP.  These attempts are largely misguided.  If simple password-based methods must be used, in almost all situations, the security of the network as a whole is increased by using PAP in preference to CHAP or MS-CHAP.  The reason is found through a simple risk analysis, which we explain in more detail below.

When PAP is used, any compromise of a system which sees the User-Password will result in that password leaking.  In contrast, when CHAP or MS-CHAP is used, those methods do not share the password, but instead a hashed transformation of it.  That hash output is in theory secure from attackers.  However, the hashes used (MD5 and MD4 respectively) are decades old, have been broken, and are known to be insecure.  Any security analysis which makes the claim that "User-Password insecure because it is protected with MD5" ignores the fact that the CHAP-Password attribute is constructed through substantially similar methods.

The difference between the two constructs is that the CHAP-Password depends on the hash of a visible Request Authenticator (or CHAP-Challenge) and the users password, while the obfuscated User-Password depends on the same Request Authenticator, and on the RADIUS shared secret.  For an attacker, the difference between the two calculations is minimal.  They can both be attacked with similar amounts of effort.

Further, any security analysis can not stop with the wire protocol.  It must include all related systems which are affected by the choice of authentication methods.  In this case, the most important piece of the system affected by these choices is the database which stores the passwords.

When PAP is used, the information stored in the database can be salted, and/or hashed in a form is commonly referred to as being in "crypt"ed form.  The incoming clear-text password then undergoes the "crypt" transformation, and the two "crypt"ed passwords are compared.  The passwords in the database are stored securely at all times, and any compromise of the database results in the disclosure of minimal information to an attacker.  That is, the attacker cannot easily obtain the clear-text passwords from the database compromise.

The process for CHAP and MS-CHAP is inverted from the process for PAP.  Using similar terminology as above for illustrative purposes, the "crypt"ed passwords are sent to the server.  The server must obtain the clear-text (or NT hashed) password from the database, and then perform the "crypt" operation on the password from the database. The two "crypt"ed passwords are then compared as was done with PAP.  This inverted process has substantial and negative impacts on security.

When PAP is used, passwords are stored in clear-text only ephemerally in the memory of an application which receives and then verifies the password.  Any compromise of that application results in the exposure of a small number of passwords which are visible at the time of compromise.  If the compromise is undetected for an extended period of time, the number of exposed passwords would of course increase.

However, when CHAP or MS-CHAP are used, all of passwords are stored in clear-text in the database, all of the time.  The database contents might be encrypted, but the decryption keys are necessarily accessible to the application which reads that database.  Any compromise of the application means that the entire database can be immediately read and exfiltrated as a whole.  The attacker then has complete access to all user identies, and all associated clear-text passwords.

The result is that when the system as a whole is taken into account, the risk of password compromise is less with PAP than with CHAP or MS-CHAP.  It is therefore RECOMMENDED that administrators use PAP in preference to CHAP or MS-CHAP.

## EAP

If more complex authentication methods are needed, there are a number of EAP methods which can be used.  These methods variously allow for the use of certificates (EAP-TLS), or passwords (EAP-TTLS {{?RFC5281}}, PEAP {{I-D.josefsson-pppext-eap-tls-eap}})) and EAP-PWD {{?RFC5931}}.

Where it is necessary to use intermediate proxies as with eduroam {{EDUROAM}} and OpenRoaming {{OPENROAMING}}, it is RECOMMENDED to use EAP instead of PAP, CHAP, or MS-CHAP.  If passwords are used, they can be can be protected via TLS-based EAP methods such as EAP-TTLS or PEAP.  Passwords can also be omitted entirely from being sent over the network, as with EAP-TLS {{?RFC9190}} or EAP-PWD {{?RFC5931}}.

We also note that the TLS-based EAP methods which transport passwords hide the passwords from intermediate RADIUS proxies.  However, they are still subject to the analysis above about PAP versus CHAP, along with the issues of storing passwords in a database.

## Eliminating Proxies

The best way to avoid compromise of proxies is to eliminate proxies entirely.  The use of dynamic peer discovery ({{?RFC7585}}) means that the number of intermediate proxies is minimized.

However, the server on the visited network still acts as a proxy between the NAS and the home network.  As a result, all of the above analysis still applies when {{?RFC7585}} peer discovery is used.

# Privacy Considerations

The primary focus of this document is addressing privacy and security considerations for RADIUS.

Deprecating insecure transport for RADIUS, and requiring secure transport means that personally identifying information is no longer sent "in the clear".  As noted earlier in this document, such information can include MAC addresses, user identifiers, and user locations.

In addition, this document suggests ways to increase privacy by minimizing the use and exchange of PII.

# Security Considerations

The primary focus of this document is addressing security and privacy considerations for RADIUS.

Deprecating insecure transport for RADIUS, and requiring secure transport means that many historical security issues with the RADIUS protocol no longer apply, or their impact is minimized.

We reiterate the discussion above, that any security analysis must be done on the system as a whole.  It is not enough to put an expensive lock on the front door of a house while leaving the window next to it open, and then declare the house to be "secure". Any approach to security based on a simple checklist is at best naive, more truthfully is deeply misleading, and at worst such practices will serve to decrease security.

Implementors and administrators need to be aware of the issues raised in this document.  They can then make the best choice for their local network which balances their requirements on privacy, security, and cost.

# IANA Considerations

There are no IANA considerations in this document.

RFC Editor: This section may be removed before final publication.

# Acknowledgements

Thanks to the many reviewers and commenters for raising topics to discuss, and for providing insight into the issues related to increasing the security of RADIUS.  In no particular order, thanks to Margaret Cullen, Alexander Clouter, and Josh Howlett.

# Changelog

* 01 - added more discussion of IPSec, and move TLS-PSK to its own document,

* 02 - Added text on Increasing the Security of Insecure Transports

--- back
