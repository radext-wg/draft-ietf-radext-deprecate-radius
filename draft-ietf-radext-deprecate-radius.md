---
title: Deprecating Insecure Practices in RADIUS
abbrev: Deprecating RADIUS
docname: draft-ietf-radext-deprecating-radius-01

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
  RFC2433:
  RFC2759:
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
  I-D.ietf-radext-tls-psk:
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
  SPOOFING:
     title: "Wi-Fi Spoofing for Fun and Profit"
     author:
       name: "Arran Cudbard-Bell"
     format:
       TXT: https://networkradius.com/articles/2021/08/04/wifi-spoofing.html
  SENSEPOST:
     title: "Cracking MS-CHAP"
     author:
       name: Sensepost
     format:
       TXT: https://github.com/sensepost/assless-chaps
  WBA:
     title: "RADIUS Accounting Assurance"
     author:
       name: "Wireless Broadband Alliance"
     format:
       TXT: https://wballiance.com/radius-accounting-assurance/
  RADEXT118:
     title: "RADIUS Accounting Assurance at IETF 118"
     author:
       name: "Wireless Broadband Alliance"
     format:
       TXT: https://youtu.be/wwmYSItcQt0?t=3953
  PWNED:
     title: "Have I been Pwned"
     author:
       name: "Troy Hunt"
     format:
       TXT: https://haveibeenpwned.com/

venue:
  group: RADEXT
  mail: radext@ietf.org
  github: freeradius/deprecating-radius.git

--- abstract

RADIUS crypto-agility was first mandated as future work by RFC 6421.  The outcome of that work was the publication of RADIUS over TLS (RFC 6614) and RADIUS over DTLS (RFC 7360) as experimental documents.  Those transport protocols have been in wide-spread use for many years in a wide range of networks.  They have proven their utility as replacements for the previous UDP (RFC 2865) and TCP (RFC 6613) transports.  With that knowledge, the continued use of insecure transports for RADIUS has serious and negative implications for privacy and security.

It is no longer acceptable for RADIUS to rely on MD5 for security.  It is no longer acceptable to send device or location information in clear text across the wider Internet.  This document therefore deprecates insecure uses of RADIUS, and mandates the use of secure TLS-based transport layers.  We also discuss related security issues with RADIUS, and give many recommendations for practices which increase security and privacy.

--- middle

# Introduction

The RADIUS protocol {{RFC2865}} was first standardized in 1997, though its roots go back much earlier to 1993.  The protocol uses MD5 {{RFC1321}} to sign some packets types, and to obfuscate certain attributes such as User-Password.  As originally designed, Access-Request packets were entirely unauthenticated, and could be trivially spoofed as discussed in {{RFC3579}} Section 4.3.2.  In order to prevent such spoofing, that specification defined the Message-Authenticator attribute ({{RFC3579}} Section 3.2) which allowed for packets to carry a signature based on HMAC-MD5.

The state of MD5 security was discussed in {{RFC6151}}, which led to the state of RADIUS security being reviewed in {{RFC6421}} Section 3.  The outcome of that review was the remainder of {{RFC6421}}, which created crypto-agility requirements for RADIUS.  {{RFC6151}} Section 2 states:

> MD5 is no longer acceptable where collision resistance is required such as digital signatures.

This text is directly applicable to RADIUS.  Despite {{RFC6151}} being over a decade old as of the time of this writing, there has been no progress towards addressing the use of MD5 in the RADIUS protocol.  This document addresses that problem.

It is no longer acceptable for RADIUS to rely on MD5 for security.  It is no longer acceptable to send device or location information in clear text across the wider Internet.  This document therefore deprecates insecure uses of RADIUS, and mandates the use of secure TLS-based transport layers.  We also discuss related security issues with RADIUS, and give many recommendations for practices which increase security and privacy.

RADIUS was historically secured with IPSec, as described in {{RFC3579}} Section 4.2:

> To address the security vulnerabilities of RADIUS/EAP,
> implementations of this specification SHOULD support IPsec
> (RFC2401) along with IKE (RFC2409) for key management.  IPsec ESP
> (RFC2406) with non-null transform SHOULD be supported, and IPsec
> ESP with a non-null encryption transform and authentication
> support SHOULD be used to provide per-packet confidentiality,
> authentication, integrity and replay protection.  IKE SHOULD be
used for key management.

The use of IPSec allowed RADIUS to be sent privately, and securely, across the Internet.  However, experience showed that TLS was in many ways simpler for implementations and deployment than IPSec.  While IPSec required operating system support, TLS was an application-space library.  This difference, coupled with the wide-spread adoption of TLS for HTTPS ensures that it was often easier for applications to use TLS than IPSec.

RADIUS/TLS {{RFC6614}} and RADIUS/DTLS {{RFC7360}} were then defined in order to meet the crypto-agility requirements of {{RFC6421}}.  RADIUS/TLS has been in wide-spread use for about a decade, including eduroam {{EDUROAM}}, and more recently OpenRoaming {{OPENROAMING}} and {{I-D.tomas-openroaming}}.  RADIUS/DTLS has seen less use across the public Internet, but it nonetheless has multiple implementations.

As of the writing of this specification, RADIUS/UDP is still widely used, even though it depends on MD5 and "ad hoc" constructions for security.  While MD5 has been broken, it is a testament to the design of RADIUS that there have been (as yet) no attacks on RADIUS Authenticator signatures which are stronger than brute-force.

However, the problems with MD5 means that if a someone can view RADIUS/UDP traffic, a hobbyist attacker can crack all possible RADIUS shared secrets of eight characters in not much more than an hour.  An more resourceful attacker (e.g. a nation-state) can crack much longer shared secrets with only modest expenditures.  See [](#cracking) below for a longer discussion of this topic.

Cracking the shared secret will also result in compromise of all passwords carried in the User-Password attribute.  Even using CHAP-Password offers minimal protection, as the cost of cracking the underlying password is similar to the cost of cracking the shared secret.  MS-CHAP ({{RFC2433}} and MS-CHAPv2 {{RFC2759}}) are significantly worse in security than PAP, as they can be trivially cracked with minimal resources, ([](#ms-chap)).

The use of Message-Authenticator does not help.  The Message-Authenticator attribute is a later addition to RADIUS, and does does not replace the original MD5-based packet signatures.  While it therefore offers a stronger protection, it does not change the cost of attacking the shared secret.  Moving to a stronger packet signatures (e.g. {{RFC6218}}) would still not fully address the issues with RADIUS, as the protocol still has privacy issues unrelated to the the security of packet signatures.

Most information in RADIUS is sent in clear-text, and only a few attributes are hidden via obfuscation methods which rely on more "ad hoc" MD5 constructions.  The privacy implications of this openness are severe.

Any observer of non-TLS RADIUS traffic is able to obtain a substantial amount of personal identifiable information (PII) about users.  The observer can tell who is logging in to the network, what devices they are using, where they are logging in from, and their approximate location (usually city).  With location-based attributes as defined in {{RFC5580}}, a users location may be determined to within 15 or so meters outdoors, and with "meter-level accuracy indoors" {{WIFILOC}}.  An observer can also use RADIUS accounting packets to determine how long a user is online, and to track a summary of their total traffic (upload and download totals).

When RADIUS/UDP is used across the public Internet, a common Wi-Fi configuration allows the location of individuals can potentially be tracked in real-time (usually 10 minute intervals), to within 15 meters.  Their devices can be identified, and tracked.  Any passwords they send via the User-Password attribute can be compromised.  Even when the packets do not contain any {{RFC5580}} location information for the user, the packets usually contain the MAC address of the Wi-Fi access point.  There are multiple services selling databases which correlate Wi-Fi access point MAC addresses and physical location down to a similar 15 meter resolution.

The implications for security and individual safety are large, and negative.

These issues are only partly mitigated when the authentication methods carried within RADIUS define their own processes for increased security and privacy.  For example, some authentication methods such EAP-TLS, EAP-TTLS, etc. allow for User-Name privacy and for more secure transport of passwords via the use of TLS.  The use of MAC address randomization can limit device information identification to a particular manufacturer, instead of to a unique device.

However, these authentication methods are not always used, or are not always available.  Even if these methods were used ubiquitously, they do not protect all of the information which is publicly available over RADIUS/UDP or RADIUS/TCP transports.  And even when TLS-based EAP methods are used, implementations have historically often skipped certificate validation, leading to password compromise ({{SPOOFING}}).  In many cases, users were not even aware that the server certificate was incorrect or spoofed, which meant that there was no way for the user to detect that anything was wrong.  Their passwords were simply handed to a spoofed server, with little possibility for the user to take any action to stop it.

## Simply using IPSec or TLS is not enough

The use of a secure transport such as IPSec or TLS ensures complete privacy and security for all RADIUS traffic.  An observer is limited to knowing rough activity levels of a client or server.  That is, an observer can tell if there are a few users on a NAS, or many users on a NAS.  All other information is hidden from all observers.  However, it is not enough to say "use IPSec" and then move on to other issues.  There are many issues which can only be addressed via an informed approach.

For example it is possible for an attacker to record the session traffic, and later crack the TLS session key or IPSec parameters.  This attack could comprise all traffic sent over that connection, including EAP session keys.  If the cryptographic methods provide forward secrecy ({{?RFC7525}} Section 6.3), then breaking one session provides no information about other sessions.  As such, it is RECOMMENDED that all cryptographic methods used to secure RADIUS conversations provide forward secrecy.  While forward secrecy will not protect individual sessions from attack, it will prevent attack on one session from being leveraged to attack other, unrelated, sessions.

AAA servers should minimize the impact of such attacks by using a total throughput (recommended) or time based limit before replacing the session keys.  The session keys can be replaced though a process of either rekeying the existing connection, or by opening a new connection and deprecating the use of the original connection.  Note that if the original connection if closed before a new connection is open, it can cause spurious errors in a proxy environment.

The final attack possible in a AAA system is where one party in a AAA conversation is compromised or run by a malicious party.  This attack is made more likely by the extensive use of RADIUS proxy forwarding chains.  In that situation, every RADIUS proxy has full visibility into, and control over, the traffic it transports.  The solution here is to minimize the number of proxies involved, such as by using Dynamic Peer Discovery ({{?RFC7585}}.

There are many additional issues on top of simply adding a secure transport. The rest of this document addresses those issues in detail.

## Overview

The rest of this document begins a summary of issues with RADIUS, and shows just how trivial it is to crack RADIUS/UDP security.  We then mandate the use of secure transport, and describe what that requirement means in practice.  We give recommendations on how current systems can be migrated to using TLS.  We give suggestions for increasing the security of existing RADIUS transports, including a discussion of the authentication protocols carried within RADIUS.  We conclude with privacy and security considerations.

As IPSec has been discussed previously in the context of RADIUS, we do not discuss it in detail to it here, other than to say it is an acceptable solution for securing RADIUS traffic.  As the bulk of the current efforts are focused on TLS, this document likewise focuses on TLS.  However, all of the issues raised here about the RADIUS protocol also apply to IPSec transport.

While this document tries to be comprehensive, it is necessarily imperfect.  There may be issues which should have been included, but which were missed due to oversight or accident.  Any reader should be aware that there are good practices which are perhaps not documented here, and bad behaviors which are likewise not forbidden.

There is also a common tendency to suggest that a particular practice is "allowed" by a specification, simply because the specification does not forbid that practice.  This belief is wrong.  That is, a behavior which is not mentioned in the specification cannot honestly be said to be "permitted" or "allowed" by that specification.  Instead, the correct description for such behaviors is that they are not forbidden.  In many cases, documents such as {{?RFC5080}} are written to both correct errors in earlier documents, and to address harmful behaviors have been seen in practice.

By their very nature, documents include a small number of permitted, required, and/or forbidden behaviors.  There are a much larger set of behaviors which are undefined.  That is, behaviors which are neither permitted nor forbidden.  Those behaviors may be good or bad, independent of what the specification says.

Outside of published specifications, there is also a large set of common practices and behaviors which have grown organically over time, but which have not been written into a specification.  These practices have been found to be valuable by implementers and administrators.  Deviations from these practices generally result in instabilities and incompatibilities between systems.  As a result, implementers should exercise caution when creating new behaviors which have not previously been seen in the industry.  Such behaviors are likely to be wrong.

It is RECOMMENDED that implementations follow widely accepted practices which have been proven to work, even if those practices are not written down in a public specification.  Failure to follow common industry practices usually results in interoperability failures.

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

In order to continue the terminology of {{RFC2865}}, we describe the Request Authenticator, Response Authenticator, and Message-Authentor as "signing" the packets.  This terminology is not consistent with modern cryptographic terms, but using other terminology could be misleading.  The reader should be assured that no modern cryptographic processes are used with RADIUS/UDP.

# Overview of issues with RADIUS

There are a large number of issues with RADIUS.   The most serious is that RADIUS sends most information "in the clear", with obvious privacy implications.

Further, as summarized in {{RFC6151}} Section 2, it has been known for over a decada that it is inappropriate to use MD5 for digital signatures and cryptography.  For traffic sent across the Internet, no protocol should depend on MD5 for security.  Even if MD5 was not insecure, computers have gotten substantially faster in the past thirty years.  This speed increase makes it possible for the average hobbyist to perform brute-force attacks to crack even seemingly complex shared secrets.

We address each of these issues in detail below.

## Information is sent in Clear Text

Other than a few attributes such as User-Password, all RADIUS traffic is sent "in the clear" when using UDP or TCP transports.  Even when TLS is used, all RADIUS traffic (including User-Password) is visible to proxies.  The resulting data exposure has a large number of privacy issues.  We refer to {{RFC6973}}, and specifically to Section 5 of that document for detailed discussion, and to Section 6 of {{RFC6973}} for recommendations on threat mitigations.

Further discussion of location privacy is given in {{?RFC6280}}, which defines an "Architecture for Location and Location Privacy in Internet Applications".  However, that work was too late to have any practical impact on the design of the RADIUS protocol, as  {{RFC5580}} had already been published.

The use of clear-text protocols across insecure networks is no longer acceptable.  Using clear-text protocols in network which are believed to be secure is not much better.  The solution is to use secure protocols, and to minimize the amount of private data which is being transported.

## MD5 has been broken

Attacks on MD5 are summarized in part in {{RFC6151}}. While there have not been many new attacks in the decade since that document was published, that does not mean that further attacks do not exist.  It is more likely that no one is looking for new attacks.

## Cracking RADIUS shared secrets is not hard  {#cracking}

The cost of cracking a a shared secret can only go down over time as computation becomes cheaper.  The issue is made worse because of the way MD5 is used to sign RADIUS packets.  The attacker does not have to calculate the hash over the entire packet, as the hash prefix can be calculated once, and then cached.  The attacker can then begin the attack with that hash prefix, and brute-force only the shared secret portion.

At the time of writing this document, an "off the shelf" commodity computer can calculate at least 100M MD5 hashes per second.  If we limit shared secrets to upper/lowercase letters, numbers, and a few "special" characters, we have 64 possible characters for shared secrets.  Which means that for 8-character secrets, there are 2^48 possible combinations.

The result is that using consumer-grade machine, it takes approximately 32 days to brute-force the entire 8 octet / 64 character space for shared secrets.  The problem is even worse when graphical processing units (GPUs) are used. A high-end GPU is capable of performing more than 64 billion hashes per second.  At that rate, the entire 8 character space described above can be searched in approximately 90 minutes.

This is an attack which is feasible today for a hobbyist. Increasing the size of the character set raises the cost of cracking, but not enough to be secure.  Increasing the character set to 93 characters means that the hobbyist using a GPU could search the entire 8 character space in about a day.

Increasing the length of the shared secret has a larger impact on the cost of cracking.  For secrets ten characters long, one GPU can search a 64-character space in about six months, and a 93 character space would take approximately 24 years.

This brute-force attack is also trivially parallelizable.  Nation-states have sufficient resources to deploy hundreds to thousands of systems dedicated to these attacks.  That realization means that a "time to crack" of 24 years is simply expensive, but does not take much "wall clock" time.  A thousand commodity CPUs are enough to reduce the crack time from 24 years to a little over a week.

Whether the above numbers are precise, or only approximate is immaterial.  These attacks will only get better over time.  The cost to crack shared secrets will only go down over time.

Even worse, administrators do not always derive shared secrets from secure sources of random numbers.  The "time to crack" numbers given above are the absolute best case, assuming administrators follow best practices for creating secure shared secrets.  For shared secrets created manually by a person, the search space is orders of magnitude smaller than the best case outlined above.  Rather than brute-forcing all possible shared secrets, an attacker can create a local dictionary which contains common or expected values for the shared secret.  Where the shared secret used by an administrator is in the dictionary, the cost of the attack can drop by multiple orders of magnitude.

It should be assumed that a hobbyist attacker with modest resource can crack most shared secrets created by people in minutes, if not seconds.

Despite the ease of attacking MD5, it is still a common practice for some "cloud" and other RADIUS providers to send RADIUS/UDP packets over the Internet "in the clear".  It is also common practice for administrators to use "short" shared secrets, and to use shared secrets created by a person, or derived from a limited character set.  Theses practice are easy to implement and follow, but they are highly insecure and SHOULD NOT be used.

Further requirements in shared secrets are given below in [](#shared-secrets).

## Tunnel-Password and CoA-Request packets {#tunnel-coa}

There are a number of security problems with the Tunnel-Password attribute, at least in CoA-Request and Disconnect-Request packets.  A full explanation requires a review of the relevant specifications.

{{RFC5176}} Section 2.3 describes how to calculate the Request Authenticator field for these packets:

~~~~
Request Authenticator

   In Request packets, the Authenticator value is a 16-octet MD5
   [RFC1321] checksum, called the Request Authenticator.  The
   Request Authenticator is calculated the same way as for an
   Accounting-Request, specified in [RFC2866].
~~~~

Where {{RFC2866}} Section 3 says:

~~~~
   The NAS and RADIUS accounting server share a secret.  The Request
   Authenticator field in Accounting-Request packets contains a one-
   way MD5 hash calculated over a stream of octets consisting of the
   Code + Identifier + Length + 16 zero octets + request attributes +
   shared secret (where + indicates concatenation).  The 16 octet MD5
   hash value is stored in the Authenticator field of the
   Accounting-Request packet.
~~~~

Taken together, these definitions mean that for CoA-Request packets, all attribute obfuscation is calculated with the Reply Authenticator being all zeroes.  In contrast for Access-Request packets, the Request Authenticator is mandated there to be 16 octets of random data.  This difference has negative impacts on security.

For Tunnel-Password, {{RFC5176}} Section 3.6 allows it to appear in CoA-Request packets:

~~~~
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
~~~~

However, {{RFC2868}} Section 3.5 says that Tunnel-Password is encrypted with the Request Authenticator:

~~~~
   Call the shared secret S, the pseudo-random 128-bit Request
   Authenticator (from the corresponding Access-Request packet) R,
~~~~

The assumption that the Request Authenticator is random data is true for Access-Request packets.  That assumption is not true for CoA-Request packets.

That is, when the Tunnel-Password attribute is used in CoA-Request packets, the only source of randomness in the obfuscation is the salt, as defined in {{RFC2868}} Section 3.5;

~~~~
 Salt
   The Salt field is two octets in length and is used to ensure the
   uniqueness of the encryption key used to encrypt each instance of
   the Tunnel-Password attribute occurring in a given Access-Accept
   packet.  The most significant bit (leftmost) of the Salt field
   MUST be set (1).  The contents of each Salt field in a given
   Access-Accept packet MUST be unique.
~~~~
 
This chain of unfortunate definitions means that there is only 15 bits of entropy in the Tunnel-Password obfuscation (plus the secret).  It is not known if this limitation makes it sufficiently easy for an attacker to determine the contents of the Tunnel-Password.  However, such limited entropy cannot be a good thing, and it is one more reason to deprecate RADIUS/UDP.

Due to the above issues, implementations and new specifications SHOULD NOT permit obfuscated attributes to be used in CoA-Request or Disconnect-Request packets.

## TLS-based EAP methods, RADIUS/TLS, and IPSec

The above analysis as to security and privacy issues focusses on RADIUS/UDP and RADIUS/TCP.  These issues are partly mitigated through the use secure transports, but it is still possible for information to "leak".

When TLS-based EAP methods such as TTLS or PEAP are used, they still transport passwords in an insecure form.  It is possible for an authentication server to terminal the TLS tunnel, and then proxy the inner data over RADIUS/UDP.  The design of both TTLS and PEAP make this process fairly trivial.  The inner data for TTLS is in Diameter AVP format, which can be trivially transformed to RADIUS attributes.  The inner data for PEAP is commonly EAP-MSCHAPv2, which can also be trivially transformed to a RADIUS EAP-Message attribute.

Similar issues apply to RADIUS/TLS and IPSec.  A proxy could terminate the secure tunnel, and forward the RADIUS packets over an insecure transport protocol.  While this process could arguably be seen as a misconfiguration issue, it is never the less possible due to the design of the RADIUS protocol.

The only solution to either issue would be to create a new protocol which is secure by design.  Unfortunately that path is not possible, and we are left with the recommendations contained in this document.

# All short Shared Secrets have been compromised

Unless RADIUS packets are sent over a secure network (IPsec, TLS, etc.), administrators SHOULD assume that any shared secret of 8 characters or less has been immediately compromised.  Administrators SHOULD assume that any shared secret of 10 characters or less has been compromised by an attacker with significant resources.  Administrators SHOULD also assume that any private information (such as User-Password) which depends on such shared secrets has also been compromised.

In conclusion, if a User-Password, or CHAP-Password, or MS-CHAP password has been sent over the Internet via RADIUS/UDP or RADIUS/TCP in the last decade, you should assume that underlying password has been compromised.

# Deprecating Insecure transports

The solution to an insecure protocol which uses thirty year-old cryptography is to deprecate the use insecure cryptography, and to mandate modern cryptographic transport.

## Deprecating UDP and TCP as transports

RADIUS/UDP and RADIUS/TCP MUST NOT be used outside of secure networks.  A secure network is one which is believed to be safe from eavesdroppers, attackers, etc.  For example, if IPsec is used between two systems, then those systems may use RADIUS/UDP or RADIUS/TCP over the IPsec connection.

However, administrators should not assume that such uses are always secure.  An attacker who breaks into a critical system could use that access to view RADIUS traffic, and thus be able to attack it.  Similarly, a network misconfiguration could result in the RADIUS traffic being sent over an insecure network.

Neither the RADIUS client nor the RADIUS server would be aware of any network misconfiguration (e.g. such as could happen with IPSec).  Neither the RADIUS client nor the RADIUS server would be aware of any attacker snooping on RADIUS/UDP or RADIUS/TCP traffic.

In contrast, when TLS is used, the RADIUS endpoints are aware of all security issues, and can enforce any necessary security policies.

Any use of RADIUS/UDP and RADIUS/TCP is therefore NOT RECOMMENDED.

## Mandating Secure transports

All systems sending RADIUS packets outside of secure networks MUST use either IPSec, RADIUS/TLS, or RADIUS/DTLS. It is RECOMMENDED, for operational and security reasons that RADIUS/TLS or RADIUS/DTLS are preferred over IPSec.

Unlike (D)TLS, use of IPSec means that applications are generally unaware of transport-layer security. Any problem with IPSec such as configuration issues, negotiation or re-keying problems are typically  presented to the RADIUS servers as 100% packet loss.  These issues may occur at any time, independent of any changes to a RADIUS application using that transport.  Further, network misconfigurations which remove all security are completely transparent to the RADIUS application: packets can be sent over an insecure link, and the RADIUS server is unaware of the failure of the security layer.

In contrast, (D)TLS gives the RADIUS application completely knowledge and control over transport-layer security.  The failure cases around (D)TLS are therefore often clearer, easier to diagnose and faster to resolve than failures in IPSec.   For example, a failed TLS connection may return a "connection refused" error to the application, or any one of many TLS errors indicating which exact part of the TLS conversion failed during negotiation.

## Crypto-Agility

The crypto-agility requirements of {{RFC6421}} are addressed in {{RFC6614}} Appendix C, and in Section 10.1 of {{RFC7360}}.  For clarity, we repeat the text of {{RFC7360}} here, with some minor modifications to update references, but not content.

Section 4.2 of {{RFC6421}} makes a number of recommendations about security properties of new RADIUS proposals.  All of those recommendations are satisfied by using TLS or DTLS as the transport layer.

Section 4.3 of {{RFC6421}} makes a number of recommendations about backwards compatibility with RADIUS.  {{RFC7360}} Section 3 addresses these concerns in detail.

Section 4.4 of {{RFC6421}} recommends that change control be ceded to the IETF, and that interoperability is possible.  Both requirements are satisfied.

Section 4.5 of {{RFC6421}} requires that the new security methods apply to all packet types.  This requirement is satisfied by allowing TLS and DTLS to be used for all RADIUS traffic.  In addition, {{RFC7360}} Section 3, addresses concerns about documenting the transition from legacy RADIUS to crypto-agile RADIUS.

Section 4.6 of {{RFC6421}} requires automated key management.  This requirement is satisfied by using TLS or DTLS key management.

We can now finalize the work began in {{RFC6421}}.  This document updates {{RFC2865}} et al. to state that any new RADIUS specification MUST NOT introduce new "ad hoc" cryptographic primitives to sign packets as was done with the Request / Response Authenticator, or to obfuscate attributes as was done with User-Password and Tunnel-Password.  That is, RADIUS-specific cryptographic methods existing as of the publication of this document can continue to be used for historical compatibility.  However, all new cryptographic work in the RADIUS protocol is forbidden.

We recognize that RADIUS/UDP will still be in use for many years, and that new standards may require some modicum of privacy.  As a result, it is a difficult choice to forbid the use of these constructs.  If an attack is discovered which breaks RADIUS/UDP (e.g. by allowing attackers to forge Request Authenticators or Response Authenticators, or by allowing attackers to de-obfuscate User-Password), the solution would be to simply deprecate the use of RADIUS/UDP entirely.  It would not be acceptable to design new cryptographic primitives in an attempt to "secure" RADIUS/UDP.

All new security and privacy requirements in RADIUS MUST be provided by a secure transport layer such as TLS or IPSec.  As noted above, simply using IPsec is not always enough, as the use (or not) of IPsec is unknown to the RADIUS application.

The restriction forbidding new cryptographic work in RADIUS does not apply to the data being transported in RADIUS attributes.  For example, a new authentication protocol could use new cryptographic methods, and would be permitted to be transported in RADIUS.  This protocol could be a new EAP method, or it could use updates to TLS. In those cases, RADIUS serves as a transport layer for the authentication method.  The authentication data is treated as opaque data for the purposes of Access-Request, Access-Challenge, etc. packets.  There would be no need for RADIUS to define any new cryptographic methods in order to transport this data.

Similarly, new specifications MAY define new attributes which use the obfuscation methods for User-Password as defined in {{RFC2865}} Section 5.2, or for Tunnel-Password as defined in {{RFC2868}} Section 3.5.  However, due to the issues noted above in [](#tunnel-coa), the Tunnel-Password obfuscation method MUST NOT be used for packets other than Access-Request, Access-Challenge, and Access-Accept.  If the attribute needs to be send in another type of packet, then the protocol design is likely wrong, and needs to be revisited.  It is again a difficult choice to forbid certain uses of the Tunnel-Password obfuscation method, but we believe that doing so is preferable to allowing sensitive data to be obfuscated with less security than the original design intent.

# Migration Path and Recommendations

We recognize that it is difficult to upgrade legacy devices with new cryptographic protocols and user interfaces.  The problem is made worse because the volume of RADIUS devices which are in use.  The exact number is unknown, and can only be approximated.  Our best guess is that at the time of this writing there are likely to be millions of RADIUS/UDP devices in daily use.  It takes significant time and effort to correct the deficiencies of all of these devices.

We therefore need to define a migration path to using secure transports.  In the following sections, we give a number of migration steps which could be done independently.  We recommend increased entropy for shared secrets.  We also mandate the use of Message-Authenticator in all Access-Request packets for RADIUS/UDP and RADIUS/TCP.  Finally, where {{RFC6614}} Section 2.3 makes support for TLS-PSK optional, we suggest that RADIUS/TLS and RADIUS/DTLS implementations SHOULD support TLS-PSK.

## Shared Secrets {#shared-secrets}

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

This script reads 96 bits of random data from a secure source, encodes it in Base32, and then makes it easier for people to work with.  The generated secrets are of the form "2nw2-4cfi-nicw-3g2i-5vxq".  This form of secret will be accepted by all implementation which supports at least 24 octets for shared secrets.

Given the simplicity of creating strong secrets, there is no excuse for using weak shared secrets with RADIUS.  The management overhead of dealing with complex secrets is less than the management overhead of dealing with compromised networks.

Over all, the security analysis of shared secrets is similar to that for TLS-PSK.  It is therefore RECOMMENDED that implementors manage shared secrets with same the practices which are recommended for TLS-PSK, as defined in {{?RFC8446}} Section E.7 and {{?RFC9257}} Section 4.

On a practical node, RADIUS implementers SHOULD provide tools for administrators which can create and manage secure shared secrets.  The cost to do so is minimal for implementors.  Providing such a tool can further enable and motivate administrators to use secure practices.

## Message-Authenticator

The Message-Authenticator attribute was defined in {{RFC3579}} Section 3.2.  The "Note 1" paragraph at the bottom of {{RFC3579}} Section 3.2 required that Message-Authenticator be added to Access-Request packets when the EAP-Message as present, and suggested that it should be present in a few other situations.   Experience has shown that these recommendations are inadequate.

Some RADIUS clients never use the Message-Authenticator attribute, even for the situations where the {{RFC3579}} text suggests that it should be used.  When the Message-Authenticator attribute is missing from Access-Request packets, it is often possible to trivially forge or replay those packets.

For example, an Access-Request packet containing CHAP-Password but which is missing Message-Authenticator can be trivially forged.  If an attacker sees one packet such packet, it is possible to replace the CHAP-Password and CHAP-Challenge (or Request Authenticator) with values chosen by the attacker.  The attacker can then perform brute-force attacks on the RADIUS server in order to test passwords.

This document therefore requires that RADIUS clients MUST include the Message-Authenticator in all Access-Request packets when UDP or TCP transport is used.

In contrast, when TLS-based transports are used, the Message-Authenticator attribute serves no purpose, and can be omitted, even when the Access-Request packet contains an EAP-Message attribute.  Servers receiving Access-Request packets over TLS-based transports SHOULD NOT silently discard a packet if it is missing a Message-Authenticator attribute.  However, if the Message-Authenticator attribute is present, it still MUST be validated as discussed in {{RFC7360}} and {{RFC3579}}.

### Server Behavior

In order to allow for migration from historic client behavior, servers SHOULD include a configuration flag which controls the above behavior.  The flag could be called "require Message-Authenticator", though other names are possible.

If the flag is set to "false", then the server behavior is unchanged from previous specifications.  If the flag is set to "true", then Access-Request packets which are missing the Message-Authenticator attribute MUST NOT be accepted by the server.  Instead, the server MUST reply immediately with an Access-Reject which contains an Error-Cause attribute with value 510 (Missing Message-Authenticator).

The purpose of this reply is two-fold.  First, the reply is a signal the client that the server is still alive.  If the packet was silently discarded, the client would have no idea why the server failed to respond.  The client could erroneously conclude that the server was down, and initiate fail-over procedures.  Such behavior leads to network instability, and should be avoided.

The second purpose of the reply is to inform the administrator of the client system as to why the Access-Request was not accepted.  The Error-Cause attribute signals the administrator as to the reason for the rejection, and indicates the corrective course of action which needs to be taken.

## Recommending TLS-PSK

Given the insecurity of RADIUS/UDP, the absolute minimum acceptable security is to use strong shared secrets.  However, administrator overhead for TLS-PSK is not substantially higher than for shared secrets, and TLS-PSK offers significantly increased security and privacy.

It is therefore RECOMMENDED that implementations support TLS-PSK.  In some cases TLS-PSK is preferable to certificates.  It may be difficult for RADIUS clients to upgrade all of their interfaces to support the use of certificates, and TLS-PSK more closely mirrors the historical use of shared secrets, with similar operational considerations.

Implementation and operational considerations for TLS-PSK are given in {{I-D.ietf-radext-tls-psk}}, and we do not repeat them here.

# Increasing the Security of RADIUS

While we still permit the use of UDP and TCP transports in secure environments, there are opportunities for increasing the security of RADIUS when those transport protocols are used.  The amount of personal identifiable information sent in packets should be minimized.  Information about the size, structure, and nature of the visited network should be omitted or anonymized.  The choice of authentication method also has security and privacy impacts.

The recommendations here for increasing the security of RADIUS transports also applies when TLS is used.  TLS transports protect the RADIUS packets from observation by from third-parties.  However, TLS does not hide the content of RADIUS packets from intermediate proxies, such as ones uses in a roaming environment.  As such, the best approach to minimizing the information sent to proxies is to minimize the number of proxies which see the RADIUS traffic.

Implementers and administrators need to be aware of all of these issues, and then make the best choice for their local network which balances their requirements on privacy, security, and cost.  Any security approach based on a simple "checklist" of "good / bad" practices is likely to result in decreased security, as compared to an end-to-end approach which is based on understanding the issues involved.

## Minimizing Personal Identifiable Information

One approach to increasing RADIUS privacy is to minimize the amount of PII which is sent in packets.  Implementers of RADIUS products and administrators of RADIUS systems SHOULD ensure that only the minimum necessary PII is sent in RADIUS.

Where possible, identities should be anonymized (e.g. {{?RFC7542}} Section 2.4).  The use of anonymized identities means that the the Chargeable-User-Identifier {{?RFC4372}} should also be used.  Further discussion on this topic is below.

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

We spend some time here in order to give recommendations for creating and managing of CUI.  We believe that these recommendations will help implementers satisfy the preceding requirements, while not imposing undue burden on the implementations.

In general, the simplest way to track CUIs long term is to associate the CUI to user identity in some kind of cache or database.  This association could be created at the tail end of the authentication process, and before any accounting packets were received.  This association should generally be discarded after a period of time if no accounting packets are received.  If accounting packets are received, the CUI to user association should then be tracked along with the normal accounting data.

The above method for tracking CUI works no matter how the CUI is generated.  If the CUI can be unique per session, or it could be tied to a particular user identity across a long period of time.  The same CUI could also be associated with multiple devices.

Where the CUI is not unique for each session, the only minor issue is the cost of the above method is that the association is stored on a per-session basis when there is no need for that to be done.  Storing the CUI per session means that is it possible to arbitrarily change how the CUI is calculated, with no impact on anything else in the system.  Designs such as this which decouple unrelated architectural elements are generally worth the minor extra cost.

For creating the CUI, that process should be done in a way which is scalable and efficient.  For a unique CUI per user, implementers SHOULD create a value which is unique both to the user, and to the visited network.  There is no reason to use the same CUI for multiple visited networks, as that would enable the tracking of a user across multiple networks.

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
>> The site-local user identifier.  For tunnelled EAP methods such as PEAP or TTLS, this could be the user identity which is sent inside of the TLS tunnel.

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
>> The site-local user identifier.  For tunnelled EAP methods such as PEAP or TTLS, this could be the user identity which is sent inside of the TLS tunnel.

However, the use of a hash-based method is RECOMMENDED.

In short, the intent is for CUI to leak as little information as possible, and ideally be different for every session.  However, business agreements, legal requirements, etc. may mandate different behavior.  The intention of this section is not to mandate complete CUI privacy, but instead to clarify the trade-offs between CUI privacy and business realities.

## User-Password Visibility

The design of RADIUS means that when proxies receive Access-Request packets, the clear-text contents of the User-Password attribute are visible to the proxy.  Despite various claims to the contrary, the User-Password attribute is never sent "in the clear" over the network.  Instead, the password is protected by TLS (RADIUS/TLS) or via the obfuscation methods defined in {{RFC2865}} Section 5.2.  However, the nature of RADIUS means that each proxy must first undo the password obfuscation of {{RFC2865}}, and then re-do it when sending the outbound packet.  As such, the proxy has the clear-text password visible to it, and stored in its application memory.

It is therefore possible for every intermediate proxy to snoop and record all user identities and passwords which they see.  This exposure is most problematic when the proxies are administered by an organization other than the one which operates the home server.  Even when all of the proxies are operated by the same organization, the existence of clear-text passwords on multiple machines is a security risk.

It is therefore NOT RECOMMENDED for organizations to send User-Password attributes in packets which are sent outside of the local organization.  If RADIUS proxying is necessary, another authentication method SHOULD be used.

Client and server implementations SHOULD use programming techniques to securely wipe passwords from memory when they are no longer needed.

Organizations MAY still use User-Password attributes within their own systems, for reasons which we will explain in the next section.

## Minimize the use of Proxies

The design of RADIUS means that even when RADIUS/TLS is used, every intermediate proxy has access to all of the information in the packet.  The only way to secure the network from such observers is to minimize the use of proxies.

Where it is still necessary to use intermediate proxies such as with eduroam {{EDUROAM}} and OpenRoaming {{OPENROAMING}}, it is RECOMMENDED to use EAP instead of PAP, CHAP, or MS-CHAP.  If passwords are used, they can be can be protected from being seen by proxies via TLS-based EAP methods such as EAP-TTLS or PEAP.  Passwords can also be omitted entirely from being sent over the network, as with EAP-TLS {{?RFC9190}} or EAP-pwd {{?RFC5931}}.

## Password Visibility and Storage

An attacker may choose to ignore the wire protocol entirely, and therefore bypass all of the issues described earlier in this document.  An attacker could instead focus on a database which holds user credentials such as account names and passwords.  At the time of this writing, databases such as {{PWNED}} claim to have records of over twelve billion user accounts which have been compromised.  Such databases are therefore highly sought-after targets.

The attack discussed in this section is dependent on vulnerabilities with the credential database, and does not assume an attacker can see or modify RADIUS traffic.  As a result, this attack applies equally well when TTLS, PEAP, or RADIUS/TLS are used.  The success of the attack depends only on how the credentials are stored in the database.  Since the choice of authentication method affects the way credentials are stored in the database, the security of that dependency needs to be discussed and explained.

Some organizations may desire to increase the security of their network by avoiding PAP, and using CHAP or MS-CHAP, instead.  These attempts are largely misguided.  If simple password-based methods must be used, in almost all situations, the security of the network as a whole is increased by using PAP in preference to CHAP or MS-CHAP.  The reason is found through a simple risk analysis, which we explain in more detail below.

### PAP Security Analysis

When PAP is used, the RADIUS server obtains a clear-text password from the user, and compares that password to credentials which have been stored in a user database.   The credentials stored in the database can be salted and/or hashed in a form is commonly referred to as being in "crypt"ed form.  The RADIUS server takes the input clear-text password, performs the same "crypt" transformation, and the two "crypt"ed passwords are compared.

Any compromise the RADIUS server will result in that clear-text password leaking.  However, in most cases, the clear-text password is available only in the memory of the RADIUS server application, and only for a short period of time.  An attacker who desires to obtain passwords for all users would have to wait for all users to log in, which can take a substantial amount of time.  During that time, an administrator may discover the breach, and resolve the issue.

In addition with PAP, the credentials in the database are stored securely at all times (presuming that the administrator only stores "crypt"ed credentials).  Any compromise of the database results in the disclosure of minimal information to an attacker.  That is, the attacker cannot easily obtain the clear-text passwords from compromising the database.

The result is that the user passwords are visible in clear-text only for a short time, and then only on the RADIUS server.  The security of this system is not as good as seen with EAP-pwd {{?RFC5931}} for example, but it is not terrible.

While the obfuscation method used for the User-Password attribute has not been shown to be insecure, it is not known to be secure.  The obfuscation method depends on calculating MD5(secret + Request Authenticator), which has a few helpful properties for an attacker.  The cost of brute-forcing short secrets is not large, [](#cracking) discusses that cost in detail.  Even for longer secrets which are humanly generated, the MD5 state for hashing the secret can be pre-calculated and stored on disk.  This process is relatively inexpensive, even for billions of possible shared secrets.  The Request Authenticator can then be added to each pre-calculated state via brute-force, and compared to the obfuscated User-Password data.

The MD5 digest is 16 octets long, and many passwords are shorter than that.  This difference means that the final octets of the digest are placed into the User-Password attribute without modificaiton.  The result is that a brute-force attack does not need to decode the User-Password and see if the decoded password "looks reasonable".  Instead, the attacker simply needs to compare the final octets of the calculated digest with the final octets of the User-Password attribute.  The result is an extremely high probability signal that the guessed secret is correct.

The only protection from this attack is to ensure that the secret is long, and derived from a cryptographically strong pseudo-random number generator.  {#shared-secrets} discusses these issues in more detail.

### CHAP and MS-CHAP Security Analysis

In contrast, when CHAP or MS-CHAP is used, those methods do not expose a clear-text password to the RADIUS server, but instead a hashed transformation of it.  That hash output is in theory secure even if an attacker can observe it.  While CHAP is believed to be secure, MS-CHAP is not, as we will see below in ([](#ms-chap)).  For the purposes of this section, we will focus on the construct of "hashed passwords", and will ignore any attacks specific to MS-CHAP.

The hash transformations for CHAP and MS-CHAP depend on a random challenge.  The intent was to increase security, but their construction makes strong requirements on the form in which user credentials are stored.

The process for performing CHAP and MS-CHAP is inverted from the process for PAP.  Using similar terminology as above for illustrative purposes, the "crypt"ed passwords are sent to the server.  The server must obtain the clear-text (or NT hashed) password from the database, and then perform the "crypt" operation on the password from the database. The two "crypt"ed passwords are then compared as was done with PAP.  This inverted process has substantial and negative impacts on security.

When CHAP or MS-CHAP are used, all of credentials are stored as clear-text passwords (or clear-text equivalent) in the database, all of the time.  The database contents might be encrypted, but the decryption keys are necessarily accessible to the application which reads that database.  Any compromise of the application means that the entire database can be immediately read and exfiltrated as a whole.  The attacker then has complete access to all user identities, and all associated clear-text passwords.

### On-the-wire User-Password versus CHAP-Password

There is one more security myth which should be put to rest about PAP versus CHAP.  There is a common belief that CHAP is more secure, because the User-Password attribute is sent "in the clear" in Access-Request packets.  This belief is false.

The User-Password attribute is obfuscated when it is sent in an Access-Request packet, using keyed MD5 and the shared secret, as defined in {{RFC2865}} Section 5.2.  At the time of this writing, no attack bettwe than brute force has been found which allows an attacker to reverse this obfuscation.

There have been claims that this obfuscation is insecure, and that it is preferable to use CHAP-Password as it does not "send the password in clear-text".  This claim is likewise false.

The CHAP-Password attribute depends on the hash of a visible Request Authenticator (or CHAP-Challenge) and the users password, while the obfuscated User-Password depends on the same Request Authenticator, and on the RADIUS shared secret.  For an attacker, the difference between the two calculations is minimal.  They can both be attacked with similar amounts of effort.   As a result, any security analysis which makes the claim that "User-Password insecure because it is protected with MD5" ignores the fact that the CHAP-Password attribute is constructed through substantially similar methods.

### PAP vs CHAP Conclusions

A careful security analyis shows that for both PAP and CHAP / MS-CHAP, the RADIUS server must have access to the clear-text version of the password.  So there is minimal difference in risk exposure between the different authentication methods if a RADIUS server is compromised.

However, when PAP is used, the user credentials can be stored securely, while such secure storage is impossible with CHAP and MS-CHAP.  There is a substantial difference in risk exposure between the different authentication methods, with PAP offering substantially higher security due to its ability to use "crypt"ed passwords.  In contrast, CHAP is highly insecure, as any database compromise results in the eimmediate exposure of all clear-text user passwords.

The result is that when the system as a whole is taken into account, the risk of password compromise is less with PAP than with CHAP or MS-CHAP.  It is therefore RECOMMENDED that administrators use PAP in preference to CHAP or MS-CHAP.

That being said, other authentication methods such as EAP-TLS {{?RFC9190}} and EAP-pwd {{?RFC5931}} do not expose clear-text passwords to the RADIUS server, and therefore can offer lower risk of password exposure.  It is RECOMMENDED that administrators avoid password-based authentication methods where at all possible.

## MS-CHAP can be reversed {#ms-chap}

MS-CHAP (v1 in {{RFC2433}} and v2 in {{RFC2759}}) has major design flaws, and should not be used outside of a secure tunnel such as with PEAP or TTLS.  As MS-CHAPv1 is less commonly used, the discussion in this section will focus on MS-CHAPv2.

Recent developments demonstrate just how easy it is to attack MS-CHAPv2 exchanges, and obtain the "NT-hash" version of the password ({{SENSEPOST}}).  The attack relies on a vulnerability in the protocol design in {{RFC2759}} Section 8.4.  In that section, the response to the MS-CHAP challenge is calculated via three DES operations, which are based on the 16-octet NT-Hash form of the password.  However, the DES operation requires 7 octet keys, so the 16-octet NT-Hash cannot be divided evenly into the 21 octets of keys required for the DES operation.

The solution in {{RFC2759}} Section 8.4 is to use the first 7 octets of the NT-Hash for the first DES key, the next 7 octets for the second DES key, leaving only 2 octets for the final DES key.  The final DES key is padded with zeros.  This construction means that an attacker who can observe the MS-CHAP2 exchange only needs to perform 2^16 DES operations in order to determine the final 2 octets of the original NT-Hash.

If the attacker has a database which correlates known passwords to NT-Hashes, then those two octets can be used as an index into that database, which returns a subset of candidate hashes.  Those hashes are then checked via brute-force operations to see if they match the original MS-CHAPv2 data.

This process lowers the complexity of cracking MS-CHAP by nearly five orders of magnitude as compared to a brute-force attack.  The attack has been demonstrated using databases which contain tens to hundreds of millions of passwords.  On a consumer-grade machine, the time required for such an attack to succeed is on the order of tens of milliseconds.

While this attack does require a database of known passwords, such databases are easy to find online, or to create locally from generator functions.  Passwords created manually by people are notoriously predictable, and are highly likely to be found in a database of known passwords.  In the extreme case of strong passwords, they will not be found in the database, and the attacker is still required to perform a brute-force dictionary search.

In fact, MS-CHAP has significantly poorer security than PAP when the MS-CHAP data is sent over the network in the clear.  When the MS-CHAP data is not protected by TLS, it is visible to everyone who can observe the RADIUS traffic.  Attackers who can see the MS-CHAP traffic can therefore obtain the underlying NT-Hash with essentially zero effort, as compared to cracking the RADIUS shared secret.  In contrast, the User-Password attribute is obfuscated with data derived from the Request Authenticator and the shared secret, and that method has not been successfully attacked.

Implementors and administrators SHOULD therefore consider MS-CHAP and MS-CHAPv2 to be equivalent in security to sending passwords in the clear, without any encryption or obfuscation.  That is, the User-Password attribute with obfuscation is substantially more secure than MS-CHAP.  MS-CHAP offers little benefit over PAP, and has many drawbacks as discussed here, and in the previous section.

This document therefore mandates that MS-CHAP or MS-CHAPv2 authentication data carried in RADIUS MUST NOT be sent in situations where the that data is visible to an observer.  MS-CHAP or MS-CHAPv2 authentication data MUST NOT be sent over RADIUS/UDP or RADIUS/TCP.  RADIUS client implementations SHOULD remove the option to use MS-CHAP from all configuration interfaces.

## EAP

If more complex authentication methods are needed, there are a number of EAP methods which can be used.  These methods variously allow for the use of certificates (EAP-TLS), or passwords (EAP-TTLS {{?RFC5281}}, PEAP {{I-D.josefsson-pppext-eap-tls-eap}})) and EAP-pwd {{?RFC5931}}.

We also note that the TLS-based EAP methods which transport passwords also hide the passwords from intermediate RADIUS proxies.  However, for the home authentication server, those EAP methods are still subject to the analysis above about PAP versus CHAP, along with the issues of storing passwords in a database.

## Eliminating Proxies

The best way to avoid compromise of proxies is to eliminate proxies entirely.  The use of dynamic peer discovery ({{?RFC7585}}) means that the number of intermediate proxies is minimized.

However, the server on the visited network still acts as a proxy between the NAS and the home network.  As a result, all of the above analysis still applies when {{?RFC7585}} peer discovery is used.

## Accounting Considered Imperfect

The use of RADIUS/UDP for accounting means that accounting is inherently unreliable.  Unreliable accounting means that different entities in the network can have different views of accounting traffic.  These differences can have multiple impacts, including incorrect views of who is on the network, to disagreements about financial obligations.  These issues are discussed in substantial detail in {{?RFC2975}}, and we do not repeat those discussions here.  We do, however, summarize a few key issues.  Sites which use accounting SHOULD be aware of the issues raised in {{?RFC2975}}, and the limitations of the suggested solutions.

Using a reliable transport such as RADIUS/TLS makes it more likely that accounting packets are delivered, and that acknowledgements are received.  Reducing the number of proxies means that there are fewer disparate systems which need to be reconciled.  Using non-volatile storage for accounting packets means that a system can reboot with minimal loss of accounting data.  Using interim accounting updates means that transient network issues or data losses can be corrected by later updates.

Systems which perform accounting are also subject to significant operational loads.  Wheres authentication and authorization may use multiple packets, those packets are sent at session start, and then never again.  In contrast, accounting packets can be sent for the lifetime of a session, which may be hours or even days.  There is a large cost to receiving, processing, and storing volumes of accounting data.

However, even with all of the above concerns addressed, accounting is still imperfect.  The obvious way to increase the accuracy of accounting data is to increase the rate at which interim updates are sent, but doing so also increases the load on the servers which process the accounting data.  At some point, the trade-off of cost versus benefit becomes negative.

There is no perfect solution here.  Instead, there are simply a variety of imperfect trade-offs.

### Incorrect Accounting Data

Even if all accounting packets were delivered and stored without error, there is no guarantee that the contents of those packets are in any way reasonable.  The Wireless Broadband Alliance RADIUS Accounting Assurance {{WBA}} group has been investigating these issues.  While the results are not yet public, a presentation was made at IETF 118 in the RADEXT working group {{RADEXT118}}.

The data presented indicated that the WBA saw just about every possible counter in RADIUS accouting packets as containing data which was blatantly wrong or contradictory.  Some examples include extremely short sessions which have impossibly large amounts of data being downloaded, or large amounts of data being downloaded while claiming neglible packet counters, leading to absurdly large packet sizes.  The only conclusion from this analysis is that RADIUS clients act as if it is better to produce incorrect accounting data rather than producing no data.  This lack of care is disappointing.

It should go without saying that accounting systems need to produce correct data.  However, {{RFC2865}} makes no requirement that the accounting data transported in RADIUS is correct, or is even vaguely realistic.  We therefore say that systems which produce accounting data MUST generate correct, accurate, and reasonably precise data.  Vendors of networking equipment SHOULD test their systems to verify that the data they produce is accurate.

# Practical Suggestions

In the interest of simplifying the above explanations, this section provides a short-form checklist of recommendations.  Following this checklist does not guarantee that RADIUS systems are secure from all possible attacks.  However, systems which do not follow this checklist are likely to be vulnerable to known attacks, and are therefore less secure than they could be.

> [ ] Do not use RADIUS/UDP or RADIUS/TCP across the wider Internet
>>
>> Exposing user identifiers, device identifiers, and locations is a privacy and security issue.

> [ ] Avoid RADIUS/UDP or RADIUS/TCP in other networks, too.
>>
>> It can take time to upgrade equipment, but the long-term goal is to entirely deprecate RADIUS/UDP.

> [ ] Use strong shared secrets
>>
>> Shared secrets should be generated from a cryptographically strong pseudo-random number generator.  They should contain at least 128 bits of entropy.  Each RADIUS client should have a unique shared secret.

> [ ] Minimize the use of RADIUS proxies.
>>
>> More proxies means more systems which could be compromised, and more systems which can see private or secret data.

> [ ] Do not proxy from secure to insecure transports
>>
>> If user information (credentials or identities) is received over a secure transport (IPSec, RADIUS/TLS, TLS-based EAP method), then proxying the protected data over RADIUS/UDP or RADIUS/TCP degrades security and privacy.

> [ ] Prefer EAP authentication methods to non-EAP methods.
>>
>> EAP authentication methods are better at hiding user credentials from observers.

> [ ] For EAP, use anonymous outer identifiers
>>
>>  There are few reasons to use individual identies for EAP.  Identifying the realm is usually enough.
>>
>> {{RFC7542}} Section 2.4 recommends that "@realm" is preferable to "anonymous@realm", which is in turn preferable to "user@realm".

> [ ] Do not use MS-CHAP outside of TLS-based EAP methods.
>>
>> MS-CHAP can be cracked with minimal effort.

> [ ] Prefer using PAP to CHAP or MS-CHAP.
>>
>> PAP allows for credentials to be stored securely "at rest" in a user database.  CHAP and MS-CHAP do not.

> [ ] Store passwords in "crypt"ed form
>>
>> Where is is necessary to store passwords, use systems such as PBKDF2 ({{?RFC8018}}.

> [ ] Regularly update to the latest cryptographic methods.
>>
>> TLS 1.0 with RC4 was acceptable at one point in time.  It is no longer acceptable.  Similarly, the current cryptographic methods will at some point will be deprecated, and replaced by updated methods.  Upgrading to recent cryptographic methods should be a normal part of operating a RADIUS server.

> [ ] Regularly deprecate older cryptographic methods.
>>
>> Administrators should actively deprecate the use of older cryptographic methods.  If no system is using older methods, then those methods should be disabled or removed entirely.  Leaving old methods enabled makes the server more vulnerable to attacks.

> [ ] Send the minimim amount of information which is needed,.
>>
>> Where proxying is used, it is a common practice is to simply forward all of the information from a NAS to other RADIUS servers.  Instead, the proxy closest to the NAS should filter out any attributes or data which are not needed by the "next hop" proxies, or by the home server.

# Privacy Considerations

The primary focus of this document is addressing privacy and security considerations for RADIUS.

Deprecating insecure transport for RADIUS, and requiring secure transport means that personally identifying information is no longer sent "in the clear".  As noted earlier in this document, such information can include MAC addresses, user identifiers, and user locations.

In addition, this document suggests ways to increase privacy by minimizing the use and exchange of PII.

# Security Considerations

The primary focus of this document is addressing security and privacy considerations for RADIUS.

Deprecating insecure transport for RADIUS, and requiring secure transport means that many historical security issues with the RADIUS protocol no longer apply, or their impact is minimized.

We reiterate the discussion above, that any security analysis must be done on the system as a whole.  It is not reaonable to put an expensive lock on the front door of a house while leaving the window next to it open, and then declare the house to be "secure". Any approach to security based on a simple checklist is at best naive, more truthfully is deeply misleading, and at worst such practices will decrease security.

Implementers and administrators need to be aware of the issues raised in this document.  They can then make the best choice for their local network which balances their requirements on privacy, security, and cost.

## Practical Implications

This document either deprecates or forbids methods and behaviors which have been common practice for decades.  While insecure practices have been viewed as tolerable, they are no longer acceptable.

# IANA Considerations

IANA is instructed to update the RADIUS Types registry, and the "Values for RADIUS Attribute 101, Error-Cause Attribute" sub-registry with the following addition:

~~~
Value,Description,Reference
502,Missing Message-Authenticator,[THIS-DOCUMENT]
~~~~

# Acknowledgements

Thanks to the many reviewers and commenters for raising topics to discuss, and for providing insight into the issues related to increasing the security of RADIUS.  In no particular order, thanks to Margaret Cullen, Alexander Clouter, and Josh Howlett.

# Changelog

* 01 - added more discussion of IPSec, and move TLS-PSK to its own document,

* 02 - Added text on Increasing the Security of Insecure Transports

* 03 - add text on CUI.  Add notes on PAP vs CHAP security

* 04 - add text on security of MS-CHAP.  Rearrange and reword many sections for clarity.

* 05 - Rework title to deprecating "insecure practices".  Clarifications based on WG feedback.

* 00 - adoption by WG.

* 01 - review from Bernard Aboba.  Added discussion on accounting, clarified and re-arranged text.  Added discussion of server behavior for missing Message-Authenticator

--- back
