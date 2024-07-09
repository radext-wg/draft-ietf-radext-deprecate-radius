---
title: Deprecating Insecure Practices in RADIUS
abbrev: Deprecating RADIUS
docname: draft-ietf-radext-deprecating-radius-02

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
  org: InkBridge Networks
  email: aland@inkbridgenetworks.com

normative:
  RFC8174:
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
  BLAST:
     title: "RADIUS/UDP Considered Harmful"
     author:
       name: Golberg, Sharon, et. al
     format:
       TXT:  https://www.blastradius.fail/pdf/radius.pdf
  DATTACK:
     title: "CHAP and Shared Secret"
     author:
       name: Alan DeKok
     format:
       TXT:  https://www.ietf.org/ietf-ftp/ietf-mail-archive/radius/1998-11.mail
  MD5-1996:
     title: "MD5 Key recovery attack"
     author:
       name: IETF RADIUS Working group
     format:
       TXT:  https://www.ietf.org/ietf-ftp/ietf-mail-archive/radius/1998-02
  EDUROAM:
     title: "eduroam"
     author:
       name: eduroam
     format:
       TXT:  https://eduroam.org
  EXPLOIT:
     title: "People’s Republic of China State-Sponsored Cyber Actors Exploit Network Providers and Devices"
     author:
       name: America's Cyber Defense Agency
     format:
       TXT:  https://www.cisa.gov/news-events/cybersecurity-advisories/aa22-158a
  BRIGGS:
     title: "Comments on the FCC’s Public Notice DA 24-308 on SS7 and Diameter Vulnerabilities"
     author:
       name: Kevin Briggs
     format:
       TXT: https://www.fcc.gov/ecfs/document/10427582404839/1
  HASHCLASH:
     title: "Project HashClash - MD5 & SHA-1 cryptanalytic toolbox"
     author:
       name: Marc Stevens
     format:
       TXT: https://github.com/cr-marcstevens/hashclash
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

The recent publication of the "Blast RADIUS" exploit has shown that RADIUS needs to be updated.  It is no longer acceptable for RADIUS to rely on MD5 for security.  It is no longer acceptable to send device or location information in clear text across the wider Internet.  This document therefore deprecates many insecure practices in RADIUS, and mandates the use of secure TLS-based transport layers.  We also discuss related security issues with RADIUS, and give many recommendations for practices which increase security and privacy.

--- middle

# Introduction

The RADIUS protocol {{RFC2865}} was first standardized in 1997, though its roots go back much earlier to 1993.  The protocol uses MD5 {{RFC1321}} to authenticate some packets types, and to obfuscate certain attributes such as User-Password.  As originally designed, Access-Request packets were entirely unauthenticated, and could be trivially spoofed as discussed in {{RFC3579}} Section 4.3.2.  In order to prevent such spoofing, that specification defined the Message-Authenticator attribute ({{RFC3579}} Section 3.2) which allowed for packets to carry an additional authentication field based on HMAC-MD5.

The insecurity of MD5 has been known for a long time.  It was first noted in relation to RADIUS in 1996 on the IETF RADIUS working group mailing list {{MD5-1996}}, which also discussed using an HMAC construct to increase security.  The first recorded comment that Access-Request packets could be spoofed was on the RADIUS working group mailing list {{DATTACK}} in 1998.  There was substantial further discussions about the lack of integrity checks on the list over the next few years.  The only recorded conclusion was the definition of Message-Authenticator as an optional HMAC-based attribute.

This lack of integrity checks for Access-Request packets was deemed acceptabled for some situations in {{RFC2869, Section 7.1}}:

> Access-Request packets with a User-Password establish the identity of
> both the user and the NAS sending the Access-Request, because of the
> way the shared secret between NAS and RADIUS server is used.

This conclusion is incorrect, because it does not address the issue of dictionary attacks, however.  The text continues with an acknowledgement that:

> Access-Request packets with CHAP-Password or EAP-Message do not have
> a User-Password attribute, so the Message-Authenticator attribute
> should be used in access-request packets that do not have a User-
> Password, in order to establish the identity of the NAS sending the
> request.

This text was non-normative, and it appears that no implementation followed this suggestion.

The packet forgery issue was further discussed in 2004 in {{RFC3579, Section 4}}, and again in 2007 in {{?RFC5080, Section 2.2.2}}.  That document suggested that implementations require the use of Message-Authenticator in order to prevent forgery:

> However, Access-Request packets not containing a Message-
> Authenticator attribute ...  may
> be trivially forged.  To avoid this issue, server implementations may
> be configured to require the presence of a Message-Authenticator
> attribute in Access-Request packets.  Requests not containing a
> Message-Authenticator attribute MAY then be silently discarded.

To our knowledge, only two RADIUS servers implemented even this limited suggestion.  At the time of publication of {{?RFC5080}}, there was no consensus to require the use of Message-Authenticator in all Access-Request packets.  If this recommendation had instead been made mandatory, then the recent Blast RADIUS vulnerability would have been prevented.

The state of MD5 security was again discussed in {{RFC6151}}, which states in Section 2:

> MD5 is no longer acceptable where collision resistance is required such as digital signatures.

That statement led to RADIUS security being reviewed in {{RFC6421, Section 3}}.  The outcome of that review was the text in the remainder of {{RFC6421}}, which created crypto-agility requirements for RADIUS.  The main outcome of those requirements was not any change to RADIUS, but instead the definition of RADIUS/TLS in {{RFC6614}}, and RADIUS over DTLS in {{RFC7360}}.  The secondary outcome was a conclusion that adding crypto-agility to RADIUS was likely not a good idea, and that standardizing RADIUS over TLS instead was significantly better.

While the RADIUS over TLS work is ongoing at the time of this writing, there are still a large number of sites using RADIUS over UDP.  Those sites need to be supported and secured until they can migrate to TLS.

To summarize, {{RFC6151}} is over a decade old as of the time of this writing.  {{?RFC5080}} is almost two decades old.  The acknowledgment that Access-Request packets lack integrity checks is almost three decades old.  Over that entire span of time, there has been no solution for addressing the use of MD5 in the RADIUS protocol.  This document offers that solution: deprecate insecure practices, and mandate secure ones.

It is no longer acceptable for RADIUS to rely on MD5 for security.  It is no longer acceptable to send device or location information in clear text across the wider Internet.  This document therefore deprecates all insecure uses of RADIUS, and mandates the use of secure TLS-based transport layers.  We also discuss related security issues with RADIUS, and give many recommendations for practices which increase security and privacy.

## RADIUS over the Internet

As the insecurity of MD5 has been well known for decades, RADIUS traffic over the Internet was historically secured with IPSec as described in {{RFC3579, Section 4.2}}:

> To address the security vulnerabilities of RADIUS/EAP,
> implementations of this specification SHOULD support IPsec
> (RFC2401) along with IKE (RFC2409) for key management.  IPsec ESP
> (RFC2406) with non-null transform SHOULD be supported, and IPsec
> ESP with a non-null encryption transform and authentication
> support SHOULD be used to provide per-packet confidentiality,
> authentication, integrity and replay protection.  IKE SHOULD be
used for key management.

The use of IPSec allowed RADIUS to be sent privately, and securely, across the Internet.  However, experience showed that TLS was in many ways simpler for implementations and deployment than IPSec.  While IPSec required operating system support, TLS was an application-space library.  This difference, coupled with the wide-spread adoption of TLS for HTTPS, ensures that it was often easier for applications to use TLS than IPSec.

RADIUS/TLS {{RFC6614}} and RADIUS/DTLS {{RFC7360}} were then defined in order to meet the crypto-agility requirements of {{RFC6421}}.  RADIUS/TLS has been in wide-spread use for about a decade, including eduroam {{EDUROAM}}, and more recently OpenRoaming {{OPENROAMING}} and {{I-D.tomas-openroaming}}.  RADIUS/DTLS has seen less use across the public Internet, but it nonetheless has multiple implementations.

However, RADIUS/UDP is still widely used, even though it depends on MD5 and "ad hoc" constructions for security.  The recent "BlastRADIUS" attack shows just how inadequate this dependency is.  The Blast RADIUS attack is discussed in more detail below, in [](#blastradius).

Even if we ignore the Blast RADIUS attack, problems with MD5 means that a hobbyist attacker who can view RADIUS/UDP traffic can brute-force test all possible RADIUS shared secrets of eight characters in not much more than an hour.  An more resourceful attacker (e.g. a nation-state) can test much longer shared secrets with only modest expenditures.  See [](#cracking) below for a longer discussion of this topic.

Determining the shared secret will also result in compromise of all passwords carried in the User-Password attribute.  Even using CHAP-Password offers minimal protection, as the cost of crackng the underlying password is similar to the cost of cracking the shared secret.  MS-CHAP ({{RFC2433}} and MS-CHAPv2 {{RFC2759}}) are significantly worse in security than PAP, as they can be completely broken with minimal resources, ([](#ms-chap)).

The use of Message-Authenticator does not change the cost of attacking the shared secret.  The Message-Authenticator attribute is a later addition to RADIUS, and does does not replace the original MD5-based packet signatures.  While that attribute therefore offers a stronger protection, it does not change the cost of attacking the shared secret.  Moving to a stronger packet signatures (e.g. {{RFC6218}}) would still not fully address the issues with RADIUS, as the protocol still has privacy issues unrelated to the the security of packet authenticators.

That is, most attributes in RADIUS are sent in clear-text, and only a few attributes such as User-Password and Tunnel-Password have their contents hidden.  Even the hidden attributes rely on "ad hoc" obfuscation methods using MD5, which are not proven to be secure.  Peoples locations can (and have) been accurately determined, and people have been tracked using location data sent insecurely across the Internet ([]{#privacy}).

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

As IPSec has been discussed previously in the context of RADIUS, we do not discuss it in detail to it here, except to say it is an acceptable solution for securing RADIUS traffic.  As the bulk of the current efforts are focused on TLS, this document likewise focuses on TLS.  However, all of the issues raised here about the RADIUS protocol also apply to IPSec transport.

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

There are a large number of issues with RADIUS.   The most serious is the Blast RADIUS vulnerability means that subject to some limitations, attackers can leverage MD5 known-prefix collisions to cause any user to be authenticated, and then be given any authorization.  Multifactor Authentication (MFA) systems can be bypassed, and the RADIUS server will in many cases not even be aware that an unauthorized user is on the network.

A related issue is that RADIUS sends most information "in the clear", with obvious privacy implications.  Even if packets use Message-Authenticator for integrity checks, it is still possible for the average hobbyist who observes RADIUS trafic to perform brute-force attacks to crack even seemingly complex shared secrets.

There is no way to fix the RADIUS protocol to address all of these issues.  The only solution is to wrap the protocol in a secure transport, such as TLS or IPSec.

We address each of these issues in detail below.

## The Blast RADIUS Vulberability {#blastradius}

The Blast RADIUS vulnerability is discussed in detail in TBD, and we only give a short summary here.  We refer the reader to the original paper for a more complete description of the issue.

The vulnerability relies on the following property of MD5, where we have texts "A", "B", "S", and "+" denotes concatenation.

> If MD5(A) == MD5(B), then MD5(A + S) == MD5(B + S)

In RADIUS, the Response Authenticator field {{RFC2865, Section 3}} is calculated via a similar construct:

> Response Authenticator = MD5(packet + secret)

If the attacker can discover two packets "A" and "B" which have the same MD5 digest, then the attacker can make the RADIUS server calculate MD5(A + secret).  The attacker then can replace packet "A" with packet "B", and send that changed packet to the client.  The client calculates MD5(B + secret), verifies the Response Authenticator, and accepts the packet.

This process is the basic concept behind the Blast RADIUS vulnerability.  We note that this attack does not expose the contents of the User-Password attribute.  Instead, it bypasses all server-side authentication, and instead fools the client into accepting a forged response.

While this issue requires that an attacker be "on path" and be able to intercept and modify packets, the meaning of "on path" is all-too-often "the entire Internet".  As such, this attack alone should be seen as a cause to deprecate RADIUS/UDP entirely.

## Information is sent in Clear Text {#privacy}

With the exception of a few attributes such as User-Password, all RADIUS traffic is sent "in the clear" when using UDP or TCP transports.  Even when TLS is used, all RADIUS traffic (including User-Password) is visible to proxies.  The resulting data exposure has a large number of privacy issues.  We refer to {{RFC6973}}, and specifically to Section 5 of that document for detailed discussion, and to Section 6 of {{RFC6973}} for recommendations on threat mitigations.

More discussion of location privacy is given in {{?RFC6280}}, which defines an "Architecture for Location and Location Privacy in Internet Applications".  However, that work was too late to have any practical impact on the design of the RADIUS protocol, as  {{RFC5580}} had already been published.

That is, any observer of non-TLS RADIUS traffic is able to obtain a substantial amount of personal identifiable information (PII) about users.  The observer can tell who is logging in to the network, what devices they are using, where they are logging in from, and their approximate location (usually city).  With location-based attributes as defined in {{RFC5580}}, a users location may be determined to within 15 or so meters outdoors, and with "meter-level accuracy indoors" {{WIFILOC}}.  An observer can also use RADIUS accounting packets to determine how long a user is online, and to track a summary of their total traffic (upload and download totals).

When RADIUS/UDP is used across the public Internet, a common Wi-Fi configuration allows the location of individuals can potentially be tracked in real-time (usually 10 minute intervals), to within 15 meters.  Their devices can be identified, and tracked.  Passwords can often be compromised by a resourceful attacker, or for MS-CHAP, by a hobbyist with a laptop.  Even when the packets do not contain any {{RFC5580}} location information for the user, the packets usually contain the MAC address of the Wi-Fi access point.  The MAC address and physical location of these devices are publicly available, and there are multiple services selling databases of this information.

These issues are not theoretical.  Recently {{BRIGGS}} noted that:

> Overall, I think the above three examples are just the tip of the proverbial iceberg of SS7 and Diameter based location and monitoring exploits that have been used successfully against targeted people in the USA.

{{BRIGGS}} continues with a statement that there have been:

> ... numerous other exploits based on SS7 and Diameter that go beyond location tracking. Some of these involve issues like (1) the monitoring of voice and text messages, (2) the delivery of spyware to targeted devices, and (3) the influencing of U.S. voters by overseas countries using text messages. 

While these comments apply to Diameter {{?RFC6733}}, the same location tracking and monitoring is also possible with RADIUS.  There is every reason to believe that similar attacks on RADIUS are still occuring, but are simply less publicized than similar attacks on Diameter.

The use of clear-text protocols across insecure networks is no longer acceptable.  Using clear-text protocols in networks which are believed to be secure is not a significantly better solution.  The correct solution is to use secure protocols, to minimize the amount of private data which is being sent, and to minimize the number of third parties who can see any traffic.

## MD5 has been broken

Attacks on MD5 are summarized in part in {{RFC6151}}.  The BlastRADIUS work substantially improved the speed of finding MD5 collisions, and those improvements are publicly available at {{HASHCLASH}}

While there have not been many other new attacks in the decade since {{RFC6151}} was published, that does not mean that further attacks do not exist.  It is more likely that no one is looking for new attacks.

## Cracking RADIUS shared secrets is not hard {#cracking}

The cost of cracking a a shared secret can only go down over time as computation becomes cheaper.  The issue is made worse because of the way MD5 is used to authenticate RADIUS packets.  The attacker does not have to calculate the hash over the entire packet, as the hash prefix can be calculated once, and then cached.  The attacker can then begin the attack with that hash prefix, and brute-force only the shared secret portion.

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

In conclusion, if a User-Password, or CHAP-Password, or MS-CHAP password has been sent over the Internet via RADIUS/UDP or RADIUS/TCP in the last decade, you should assume that the underlying password has been compromised.

# The Blast RADIUS Attack

This section gives some more detail on the attack, so that the reader can be informed as to why this document makes specifc recommendations.

An "on path" attacker can inject one or more Proxy-State attributes with special contents into an Access-Request packet. The Proxy-State attribute itself will not trigger any overflow or “out of bounds” issue with the RADIUS client or server.  Instead, the contents of the attributes will allow the attacker to create an MD5 known-prefix collision when the server calculates the Response Authenticator.  In effect, the attacker uses the RADIUS server, and its knowledge of the shared secret, to unknowingly authenticate packets which it has not created.

The behavior of the Proxy-State attribute is extremely useful to this attack.  The attribute is defined in {{RFC2865, Section 5.33}} as an opaque token which is sent by a RADIUS proxy, and is echoed back by RADIUS servers.  That is, the contents of the attribute are never examined or interpreted by the RADIUS server.  Even better, testing shows that all RADIUS clients will simply ignore any unexpected Proxy-State attributes which they receive.  And finally, implementations generally add Proxy-State to the end of response packets, which simplifies the attack.

This attribute is therefore ideally suited to an attackers purpose of injecting arbitrary data into packets, without that data affecting client or server behavior.   It is not clear why Proxy-State is defined this way, as the records of the original IETF RADIUS working group have either been lost to time, or are missing.  However, the design and implementation of Proxy-State is just about ideal for for leveraging the attack.

While it is possible to use other attributes to achieve the same effect, the use of Proxy-State is simple, and is sufficient to trigger the issue.

The injected data and resulting MD5 collision allows the attacker to modify the packet contents almost at will, and the client will still accept the modified packet as being authentic.  The attack allows nearly arbitrary attributes to be added to the response.  Those attributes are simply part of the MD5 collision calculation, and do not increase the cost of that calculation.

Again, since the RADIUS server can be convinced to authenticate packets using a prefix chosen by the attacker, there is no need for the attacker to know the shared secret.

The attack is implemented via the following steps, which are numbered the same as in the original paper.

1. The attacker requests network access from the RADIUS client (NAS).  This action triggers the NAS to send an Access-Request packet to the RADIUS server.

2. The Access-Request is observed to obtain its contents, including the Request Authenticator field.  The attacker prevents this packet from reaching the server until the MD5 collision data has been calculated..  The NAS will retransmit the packet one or more times after a delay, giving the attacker time to calculate the chosen prefix.

3. Some external resources are used to calculate an MD5 collision using the Request Authenticator, and the expected contents of an Access-Reject.  As Access-Reject packets are typically empty (or can be observed), the expected packet contents are known in their entirety.

4. Once an MD5 collision is found, the resulting data is placed into one or more Proxy-State attributes in the previously seen Access-Request.  The attacker then sends this modified Access-Request to the RADIUS server.

5. The RADIUS server responds with an Access-Reject, and includes the Proxy-State attributes from the modified Access-Request packets.

6. The attacker discards the original Access-Reject, and uses the chosen prefix data to create a different (i.e. modified) response, such as an Access-Accept.  Other authorization attributes such as VLAN assignment can also be add, modified, or deleted.

7. The NAS receives the modified Access-Accept, verifies that the Response Authenticator is correct, and gives the user access, along with the attackers desired authorization.

The result of this attack is a near-complete compromise of the RADIUS protocol.  The attacker can cause any user to be authenticated.  The attacker can give almost any authorization to any user. 

While the above description uses Access-Reject responses, we reiterate that the root cause of the vulnerability is in the Access-Request packets.  The attack will therefore succeed even if the server responds with Access-Accept, Access-Challenge, or Protocol-Error.

In addition to forging an Access-Accept for a user who has no credentials, the attacker can control the traffic of known and authenticated users.  Many modern Broadband Network Gateways (BNG)s, Wireless Lan Controllers (WLCs), and Broadband Remote Access Servers (BRAS) support configuring a dynamic HTTP redirect using Vendor Specific Attributes (VSA)s.  These VSAs are not protected by the shared secret, and could be injected into an Access-Accept in order to redirect a users traffic.  The attacker could then set up a malicious website to launch Zero-Day/Zero-Click attacks, driving subscribers to the website using an HTTP redirect.  This issue is compounded by the fact that many devices perform automatic HotSpot 1.0 style walled garden discovery.  The act of simply connecting to their home WiFi connect could be enough to compromise a subscriber's equipment.

The result of the attack is a near-total compromise of RADIUS security.  The following subsections define mitigations which can be used to protect clients and servers from this attack when using RADIUS/UDP or RADIUS/TCP.  However, we reiterate here, and in the rest of this document that the only long-term solution is to deprecate insecure transports entirely.

## Changes to RADIUS

There are a number of changes required to both clients and servers in order for all possible attack vectors to be closed.  Implementing only some of these mitigations means that an attacker could bypass the partial mitigations, and therefore still perform the attack.

This section outlines the mitigation methods which protect systems from this attack, along with the motivation for those methods.

We note that unless otherwise noted, the discussion here applies only to Access-Request packets, and to responses to Access-Request (i.e. Access-Accept, Access-Reject, Access-Challenge, and Protocol-Error packets).  All behavior involving other request and response packets MUST remain unchanged.

Similarly, the recommendations in this section only apply to UDP and TCP transport.   They do not apply to TLS transport, and no changes to TLS transport are needed to protect from this attack.  Clients and servers MUST NOT apply any of the new configuration flags to packets sent over TLS or DTLS transport.  Clients and servers MAY include Message-Authenticator in request and responses packets which are sent over TLS or DTLS transports, but the attribute serves no security purpose.

We recognize that implementing these mitigation may require a significant amount of effort.  There is a substantial amount of work to perform in updating implementations, performing interoperability tests, changing APIs, changing user interfaces, and updating documentation.  This effort cannot realistically be done in a short time frame.

There is therefore a need for an immediate and short-term action which can be implemented by RADIUS clients and servers which is both simple to do, and which is known to be safe.  The recommendations in this section are known to protect implementations from the attack; to be simple to implement; and also to allow easy upgrade without breaking existing deployments.

The mitigation methods outlined here allow systems to both protect themselves from the attack, while not breaking existing networks.  There is no global “flag day” required for these changes.  Systems which implement these recommendations are fully compatible with legacy RADIUS implementations, and can help protect those legacy implementations.  However, when these mitigations are not implemented, systems are still vulnerable to the attack.

Note that in some network architectures, the attack can be mitigated simply by upgrading the RADIUS server, so that it sends Message-Authenticator as the first attribute in all responses to Access-Request packets.  However, the goal of this specification is to fix all architectures for RADIUS systems, rather than a limited subset.  We therefore mandate new behavior for all RADIUS clients and server, while acknowledging that some organizations may choose to not deploy all of the new functionality.  For overall network security and good practice. we still recommend that all RADIUS clients and servers be upgraded, and have the new "require Message-Authenticator" flag set.

### Clients and Access-Request

Clients MUST add Message-Authenticator to all Access-Request packets.

This behavior MUST NOT be configurable.  Disabling it would open the system up to attacks, and would prevent the other mitigation methods from working.  The root cause of the attack is that Access-Request packets lack integrity checks, so the most important fix is to add integrity checks to those packets.

The Message-Authenticator SHOULD be the first attribute in all Access-Request packets.  That is, it should be placed immediately after the packet header.

From a cryptographic point of view, the location of Message-Authenticator does not matter, as it just needs to exist somewhere in the packet.  However, as discussed below for Access-Accept etc. packets, the location of Message-Authenticator does matter.  It is better to have consistent and clear messaging for addressing this attack, instead of having different recommendations for different kinds of packets

All RADIUS servers will validate the Message-Authenticator attribute correctly when that attribute is received in a packet.  We are not aware of any RADIUS servers which will reject or discard Access-Request packets if they unexpectedly contain a Message-Authenticator attribute.

This behavior has been enabled in the FreeRADIUS server for over a decade, and there have been no reports of interoperability problems.  It is therefore safe for all clients to immediately implement this requirement.

However, many existing RADIUS clients do not send Message-Authenticator.  It also may be difficult to upgrade some client equipment, as the relevant vendor may have gone out of business, or may have marked equipment as “end of life” and thus unsupported.  It is therefore necessary to both work with such systems by not breaking existing RADIUS deployments, while at the same time protecting them as much as practically possible.

### Servers and Access-Request

Servers MUST have a per-client boolean configuration flag, which we call “require Message-Authenticator”.  The default value for this flag must be “false” in order to maintain compatibility with legacy clients.

When this flag is set to “true”, any Access-Request packets which do not contain Message-Authenticator MUST be silently discarded.  This action protects the server from packets which have been modified in transit to remove Message-Authenticator.

When this flag is set to “false”, RADIUS servers MUST follow legacy behavior for validating, and enforcing the existence of Message-Authenticator in Access-Request packets.  For example, enforcing the requirement that all packets containing EAP-Message also contain a Message-Authenticator attributes, but otherwise accepting and validating the Message-Authenticator attribute if it is present, but taking no action if the attribute is missing.

The reason for the historical default value to be “false” is that many RADIUS clients do not send the Message-Authenticator attribute in all Access-Request packets.  Defaulting to a value of "true" means that the RADIUS server would be unable to accept packets from many legacy RADIUS clients, and existing networks would break.

If this flag is “false”, then the server can be vulnerable to the attack, even if the client has been updated to always send Message-Authenticator in all Access-Requests.    The attacker could simply strip the Message-Authenticator from the Access-Request, and proceed with the attack as if client had not been updated.  As a result, this flag MAY be set to “false” if the client is a NAS, and SHOULD NOT be set to "false" for proxies.

Administrators can set this flag to “true” for clients which send Message-Authenticator, and leave the flag as “false” for clients which cannot be upgraded.

We note that "Section 7.2 of the paper" has the following comment about the FreeRADIUS server, which has has this configuration option since 2008:

> If support for these old clients is not required, enabling this option would make our attacks infeasible. 

Every network administrator MUST set this flag to "true" for all clients which send Message-Authenticator.

While servers must validate the contents of Message-Authenticator,  they MUST NOT check the location of that attribute.  There is no different meaning in RADIUS if Message-Authenticator is the first, second, or last attribute in a packet.  Servers MUST accept a RADIUS packet as valid if it passes authentication checks, no matter the location of the Message-Authenticator attribute.

Unfortunately, there is no way for clients and servers to negotiate configuration in RADIUS/UDP or RADIUS/TCP.  The server cannot determine if the packets are discarded due to an attack, or if they are discarded due to a mismatched configuration between client and server.  The server SHOULD therefore log the fact that the packet was discarded (with rate limits) in order to inform the administrator that either an attack is underway, or that there is a configuration mismatch between client and server. 

As a special corner case for debugging purposes, instead of discarding the packet, servers MAY immediately instead send a Protocol-Error or Access-Reject response packet.  This packet MUST contain a Message-Authenticator attribute as the first attribute in the packet, otherwise an attacker could turn this response into an Access-Accept.  The response MUST also contain an Error-Cause attribute with value 510 (Missing Message-Authenticator).  The server MUST not send this response by default, as it this could cause the server to respond to forged Access-Request packets.  This behavior MUST be enabled only when specifically configured by an administrator.  It MUST also be rate-limited, as there is no need to signal this error on every packet received by the server.

The purpose of this Protocol-Error packet is to allow administrators to signal misconfigurations between client and server.  It is intended to only be used temporarily when new client to server connections are being configured, and MUST be disabled permanently once the connection is verified to work.

As RADIUS clients are upgraded over time, RADIUS servers can eventually enable the “require Message-Authenticator” flag by default. 

The next question is how to protect systems when legacy clients do not send Message-Authenticator.

### Updated Servers and Legacy Clients

Where it is not possible for a server to require Message-Authenticator in Access-Request packets, it is still possible to largely protect servers from the attack.  We can motivate the solution by observing that the attack requires the server to receive packets containing Proxy-State, while “real” clients (i.e. not proxies) will never send Proxy-State.

The mitigations in this section MUST NOT be used when the "require Message Authenticator" flag is set to "false".

A RADIUS server can still partially protect itself when the "require Message Authenticator" flag is set to "false", by adding an additional per-client boolean configuration flag, which we call “limit Proxy-State”.  The intention here is to permit the server to accept Access-Request packets which are missing Message-Authenticator, but also to discard the modified packets which are a vector for this attack.

When the flag is set to "false", RADIUS servers MUST follow legacy behavior for enforcing the existence of Message-Authenticator in Access-Request packets, as with the previous section.

When the flag is set to "true", RADIUS servers MUST require that all Access-Request packets which contain a Proxy-State attribute also contain a Message-Authenticator attribute.  This flag is motivated by the realization that NASes which do not send Message-Authenticator in Access-Request packets also never send Proxy-State.  It is therefore safe to add a flag which checks for Proxy-State, because well-behaving NASes will never send it.  The only time the server will see a Proxy-State from a NAS is when the attack is taking place.

As RADIUS proxies are now mandated to add Proxy-State to all proxied packets, this flag MAY be set only when the client is a NAS which cannot be upgraded, and MUST NOT be set in other situations.  Specifically, the flag MUST NOT be set when the client is a proxy,  the “require Message-Authenticator” flag MUST be used instead.

The recommended behavior for this flag is to not just drop packets which contain Proxy-State, but instead to drop them only if they contain Proxy-State, and also do not contain Message-Authenticator.  The additional checks allow the server to be more flexible in what packets it accepts, without compromising on security.

This flag is necessary because it may not be possible to upgrade some RADIUS clients for an extended period of time, or even at all.  Some products may no longer be supported, or some vendors have gone out of business.  There is therefore a need for RADIUS servers to protect themselves from to this attack, while at the same time being compatible with legcy RADIUS client implementations.

The combination of these two flags is that we both obtain the positive result that the systems are protected as much as feasible, while at the same time avoiding the negative result of creating interoperability issues.  The local RADIUS server will be protected from attacks on the client to server path, so long as one of the two flags is set. 

While it is theoretically possible to perform the Blast RADIUS attack via attributes other than Proxy-State, no such exploits are known at this time.  Any such exploit would require that the server receive fields under the attackers control (e.g. User-Name), and echo them back in a response.  Such attacks are only possible when the server is configured to behave this way, which is not the default behavior for most servers.

It is therefore RECOMMENDED that servers only echo back user-supplied data in responses when the "require Message-Authenticator" flag is set to "true".  No other configuration is known to protect from all possible variants of this attack.

These two configuration flags will not protect clients (NASes or proxies) from servers which have not been upgraded or configured correctly.  More behavior changes to servers and clients are required. 

### Server Responses to Access-Request

Servers MUST add Message-Authenticator as the first attribute in all responses to Access-Request packets.  That is, all Access-Accept, Access-Reject, Access-Challenge, and Protocol-Error packets.  The attribute MUST be the first one in the packet, immediately after the 20 octet packet header.

Adding Message-Authenticator as the first attribute means that for the purposes of MD5 known prefixes attacks, essentially the entire packet is an unknown suffix.  The attacker is therefore unable to leverage a known prefix, and the vulnerability is mitigated.

This behavior also protects one client to server hop, even if the server does not require Message-Authenticator in Access-Request packets, and even if the client does not examine or validate the contents of the Message-Authenticator.

We note that in contrast, adding a Message-Authenticator to the end of response packets will not mitigate the attack.  When the Message-Authenticator is the last attribute in a packet, the attacker can treat the Message-Authenticator as an unknown suffix, as with the shared secret.  The attacker can then calculate the prefix as before, and have the RADIUS server authenticate the packet which contains the prefix.  The attack is only prevented when the Message-Authenticator is the first attribute in the packet, i.e. when no other attributes appear in the packet before Message-Authenticator.  We direct the reader to Section 7.2 of the paper for a more complete description of these issues.

The location of the Message-Authenticator attribute is critical to protect legacy clients which do not verify that attribute. Many legacy clients do not send Message-Authenticator in Access-Request packets, and therefore are highly likely to not validate it in responses to those Access-Requests.  Upgrading all of these clients may be difficult, or in some cases impossible.  It is therefore important to have mitigation factors which protect those systems.

The requirement above to send Message-Authenticator first in response packets therefore protects those legacy clients, as the known prefix attack cannot occur.  The client will still verify the Response Authenticator for the unmodified packet, and will then accept the unmodified, and properly authenticated packet.

As it is difficult to upgrade both clients and servers simultaneously, we also need a method to protect clients when the server has not been updated.  That is, clients cannot depend on the Message-Authenticator existing in response packets.  Clients need to take additional steps to protect themselves, independent of any server updates.

### Clients Receiving Responses

As discussed above, an attacker can remove or hide Message-Authenticator from the response packet, and still perform the attack.  Clients (and proxies acting as clients) therefore MUST also implement a configuration flag “require Message-Authenticator”, which mirrors the same flag for servers.  When the flag is set to "false", RADIUS clients MUST follow legacy behavior for enforcing the existence of Message-Authenticator in response packets.

When the flag is set to “true”, the client MUST silently discard (as per RFC 2865 Section 1.2) any response to Access-Request packets which does not contain a Message-Authenticator attribute.  This check MUST be done before the Response Authenticator or Message-Authenticator has been verified.  No further processing of the packet should take place. 

While a client MUST validate the contents of Message-Authenticator, it MUST NOT check the location of that attribute.  There is no different meaning in RADIUS if Message-Authenticator is the first, second, or last attribute in a packet.  Clients MUST accept a RADIUS packet as valid if it passes authentication checks, no matter the location of the Message-Authenticator attribute.

That is, if the Message-Authenticator exists anywhere in the response packet, and that attribute passes validation, then the client can trust that the response from the server has not been modified by an attacker.

When the response is discarded, the client MUST behave as if the response was never received.  That is, any existing retransmission timers MUST NOT be modified as a result of receiving a packet which is silently discarded.

Unfortunately, the client cannot determine if the packets were discarded due to an attack, or if they were discarded due to a mismatched configuration between client and server.  The client SHOULD log the fact that the packet was discarded (with rate limits) in order to inform the administrator that either an attack is underway, or that there is a configuration mismatch between client and server.  The solution to the inability of legacy RADIUS to perform signaling and capability negotiation is not to update the protocol.  Instead, the solution is to move to TLS.

### Status-Server

While the attack works only for Access-Request packets, Access-Accept or Access-Reject can also be sent in response to Status-Server packets.  In order to simplify client implementations, servers MUST follow the above recommendations relating to Message-Authenticator when sending Access-Accept or Access-Reject packets, even if the original request was Status-Server.

This requirement ensures that clients can examine responses independent of any requests.  That is, the client code can do a simple verification pass of response packets prior to doing any more complex correlation of responses to request.

## Related Issues

This section contains discussions of related issues which do not involve changes to the RADIUS protocol.

### Other Mitigations

RADIUS clients (but not proxies) MAY also check for the existence of the Proxy-State attribute in responses to Access-Request packets.  Since a NAS / GGSN / etc. is not a RADIUS proxy, it will never sent a Proxy-State in an Access-Request,, and therefore responses to that Access-Request will never contain a Proxy-State attribute.  In addition, no standards compliant RADIUS server will respond with a Proxy-State when the Access-Request does not contain a Proxy-State attribute.

If the response to an Access-Request does contain a Proxy-State attribute, then the client can safely discard the packet, knowing that it is invalid.  This behaviour SHOULD always be enabled, and should not be configurable.

This behavior will also help protect the client when the new configuration flags described here are not set.

However, as noted in the Section 7.7 of the Blast RADIUS paper, this behavior alone is not sufficient to protect the client.  The attacker can not only hide a Message-Authenticator if it is last in a response packet, the attacker can use similar techniques to hide Proxy-State attributes.  The client would then see a response which does not contain Message-Authenticator or Proxy-State.  Instead, the client would see a response which does contain attributes that it is known to ignore, such as a Vendor-Specific attribute from an unknown vendor.

### Documentation and Logging

It is RECOMMENDED that RADIUS server implementations document the behavior of these flags in detail, including how they help protect against this attack.  We believe that an informed administrator is more likely to engage in secure practices.

Similarly, when either of the above flags cause a packet to be discarded, the RADIUS server SHOULD log a descriptive message (subject to rate limiting) about the problematic packet.  This log is extremely valuable to administrators who wish to determine if anything is going wrong, and what to do about it.

### Alternative Solutions

An alternative configuration flag with a similar effect to the “limit Proxy-State” flag could be one called “this client is a NAS, and will never send Proxy-State”.  The intention for such a flag would be to clearly separate RADIUS proxies (which always send Proxy-State), from NASes (which will never send Proxy-State).  When the flag is set for a client, the server could then discard Access-Request packets which contain Proxy-State.  Alternatively, the server could also discard Proxy-State from all responses sent to that client.

Such a flag, however, depends on network topology, and fails to correct the underlying lack of packet authenticity and integrity.  The flag may also work for one NAS, but it is likely to be incorrect if the NAS is replaced by a proxy.  Where there are multiple different pieces of NAS equipment behind a NAT gateway, flag is also likely to be correct for some packets, and incorrect for others.

Setting configuration flags by the desired outcome is preferable to setting flags which attempt to control network topology.

It may be tempting to come up with other "ad hoc" solutions to this vulnerability.  Such solutions are NOT RECOMMENDED, as they are likely to either break existing RADIUS deployments, or else they will not prevent the attack.  The mitigations described in this document not only prevent the attack, they do so without affecting normal RADIUS operation.  There is therefore no reason to use any other methods.

Other attempted mitigation factors are discussed in the "Blast RADIUS" document.  For example, "Blast RADIUS" Section 7.4 explains why decreasing timeouts simply increases the cost of the attack without preventing it.  Decreasing timeouts also can negatively affect normal traffic.

"Blast RADIUS" Section 7.7 explains why validating Proxy-State, or looking for unexpected Proxy-State does not help.  The attacker can likely just change the nature of the attack, and bypass those checks.

There is no reason to implement “ad hoc” solutions when a solution exists which has passed reviews by both the Blast RADIUS cryptographers, and by the RADIUS working group.  There is every reason to believe that cryptographic operations designed by experts and subject to rigorous peer review are better than random guesses made by programmers lacking relevant cryptographic and RADIUS experience.

### Network Operators

The most important outcome of this attack for network operators is that where possible, all RADIUS traffic should use TLS transport between client and server.  

All other methods to mitigate the attack are less secure, they still fail at adding privacy, and are therefore less useful.  We recognize that not all networking equipment supports TLS transport, so we therefore give additional recommendations here which operators can follow to help mitigate the attack.

All networking equipment should be physically secure.  There is no reason to have critical portions of networking infrastructure physically accessibly to the public.  Where networking equipment must be in public areas (e.g. access points), that equipment SHOULD NOT have any security role in the network.  Instead, any network security validation or enforcement SHOULD be done by separate equipment which is in a physically secure location.

It is RECOMMENDED that all RADIUS traffic be sent over a management VLAN.  This recommendation should be followed even if TLS transport is used.  There is no reason to mix user traffic and management traffic on the same network.

Using a management network for RADIUS traffic will generally prevent anyone other than trusted administrators from performing this attack.  We say “generally”, because security is limited by the least secure part of the network.  If a network device has some unrelated vulnerability, then an attacker could exploit that vulnerability to gain access to the management network.  The attacker would then be free to exploit this issue.

Only the use of TLS will prevent such attacks from being chained together.

Similarly, there are few reasons to use RADIUS/TCP.  Any system which supports RADIUS/TCP likely also supports TLS, and that should be used instead.

Finally, any RADIUS/UDP or RADIUS/TCP traffic MUST NOT be sent over public networks such the Internet. This issue is discussed in more detail elsewhere in this document.

## Limitations of the Mitigations

The above mitigations have some limitations.

### Vulnerable Systems

A RADIUS server is vulnerable to the attack if it does not require that all received Access-Request packets contain a Message-Authenticator attribute.  This vulnerability exists for many common uses of Access-Request, including packets containing PAP, CHAP, MS-CHAP, or packets containing “Service-Type = Authorize-Only”.   The vulnerability is also transitive.  If any RADIUS server in a proxy chain is vulnerable, then the attack can succeed, and the attacker can gain unauthenticated and/or unauthorized access.

Simply having the Message-Authenticator attribute present in Access-Request packets is not sufficient.  In order to be protected, a server must require that the attribute is present, and discard packets where it is missing.  Similarly, the client must also require that the attribute is present, and discard packets where it is missing.

The attack is fully mitigated only when both sides of the RADIUS conversation are updated and configured correctly.

### Unaffected Systems

There are a number of systems which are not vulnerable to this attack.  The most important ones are systems which only perform EAP authentication, such as with 802.1X / WPA enterprise.  The EAP over RADIUS protocol is defined in {{RFC3579, Section 3.3}} which states explicitly:

> If any packet type contains an EAP-Message attribute it MUST also contain a Message-Authenticator.

This requirement reiterates that of {{?RFC2869, Section 5.13}}, which defines EAP-Message and Message-Authenticator, but which does not get into details about EAP.

This requirement is enforced by all known RADIUS servers.  As a result, when roaming federations such as eduroam use RADIUS/UDP, it is not possible for the attacker to forcibly authenticate users, but it may be possible for the attacker to control the authorization attributes for known and valid users.

Other roaming groups such as OpenRoaming require the use of TLS, and are not vulnerable.  Other roaming providers generally use VPNs to connect disparate systems, and are also not vulnerable.

802.1X / WPA enterprise systems have an additional layer of protection, due to the use of the master session keys (MSK) which are derived from the EAP authentication. method  These keys are normally carried in the MS-MPPE-Recv-Key and MS-MPPE-Send-Key attributes in the Access-Accept packet.  The contents of the attributes are obfuscated via the same method used for Tunnel-Password.

While an attacker can perhaps force an Access-Accept in some situations, or strip the Message-Authenticator from packets, it is not currently possible for an attacker to see, modify, or create the correct MSK for the EAP session.  As a result, when 802.1X / WPA enterprise is used, even a successful attack on the Access-Accept packet would likely not result in the attacker obtaining network access.

### The Weakest Link

RADIUS security is done on a “hop by hop” basis, which means that an attacker can take advantage of the weakest link in a proxy chain, in order to attack other systems which have fully implemented the above mitigations.  If the packets are passed through one or more proxies, then any one vulnerable proxy will still allow the attack to take place.

If proxies must be used, every single hop in the proxy chain SHOULD be verified to follow the highest level of security, otherwise all security will be lost.

Even worse, proxies have full control over packet contents.  A malicious proxy can change a reject into an accept, and can add or delete any authorization attributes it desires.  While proxies are generally part of a trusted network, there is every benefit in limiting the number of participants in the RADIUS conversation.

Proxy chains SHOULD therefore be avoided where possible, and {{?RFC7585}} dynamic discovery should be used where possible.  RADIUS clients and servers SHOULD also be configured with static IP addresses, and static routes.  This static configuration also protects them from DHCP related attacks where an attacker spoofs DHCP to cause clients or servers to route packets through the a system of the attackers choice.

## Note on Proxy-State

As the Blast RADIUS paper points out in Appendix A:

> The presence of this attribute makes the protocol vulnerability much simpler to exploit than it would have been otherwise.

To see why this the case, we go back to the original discussion in May 1995:

> The RADIUS proxy may place any state information (subject to the length
> limitations of a RADIUS attribute) that it will need to transform a
> reply from its server into a reply to its client.  This is typically
> the original authenticator, identifier, IP address and UDP port number
> of the proxy's RADIUS client.

There appear to be few, if any, RADIUS servers which implement this suggestion.  In part because later discussions note:

> This works only if the NAS is
> prepared to accept replies from a proxy server for a request issued to
> a different server.

This stateless proxy design has a number of additional issues, most notably violating the {{?RFC3539}} "end-to-end" principle.  It therefore negatively impacts the stability of a RADIUS proxy system.

This definition for Proxy-State later changed in {{RFC2865, Section 5.33}} to

> Usage of the Proxy-State Attribute is implementation dependent.  A
> description of its function is outside the scope of this
> specification.

In practice, the utility of Proxy-State is limited to detecting proxy loops.  Proxies can count the number of Proxy-State attributes in received packets, and if the total is more than some number, then a proxy loop is likely.

It is likely that a "hop count" attribute would likely have been simpler to implement, but even in 1996, it was likely difficult to change due to multiple implementations.

## Intrusion Detection Systems

Intrusion detection systems can be updated to detect and/or warn about the attack with the following rules.  In the interests of brevity and generality, the rules are written as plain text, and not as code.

1. Access-Request does not contain a Message-Authenticator attribute
   > Action: Warn the administrator that the system is vulnerable, and should be upgraded
2. Access-Accept, Access-Reject, or Access-Challenge does not contain a Message-Authenticator attribute
   > Action: Warn the administrator that the system is vulnerable, and should be upgraded
3. Access-Accept, Access-Reject, or Access-Challenge contains a Message-Authenticator attribute, but it is not the first attribute in the packet
   > Action: Warn the administrator that the system is vulnerable, and should be upgraded
4. Access-Request packet received by a RADIUS server contains Proxy-State, when the RADIUS client is a NAS
   > Action: Alert that an attack is likely taking place.
   > Note that the check should be for packets received by the RADIUS server, and not for packets sent by the NAS.  The attack involves packets being modified after they are sent by the NAS, and before they are received by the RADIUS server.
5. Access-Accept, Access-Reject, or Access-Challenge sent by a RADIUS server contain Proxy-State, when the RADIUS client is a NAS.
   > Action: Alert that an attack is likely taking place.
   > Note that the check should be for packets sent by the RADIUS server, and not for packets received by the NAS.  The attacker can modify packets to "hide" Proxy-State in another attribute, such as Vendor-Specific.
6. Any RADIUS traffic is sent over UDP or TCP transport, without IPSec or TLS.
   > Action: Warn that the system uses deprecated transport protocols, and should be upgraded.
7. Any RADIUS traffic is sent external to the organization over UDP or TCP transport, without IPSec or TLS.
   > Action: Warn that this is an insecure configuration, and can expose users private data, identities, passwords, locations, etc. to unknown attackers.

# Deprecating Insecure Transports

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

We can now finalize the work began in {{RFC6421}}.  This document updates {{RFC2865}} et al. to state that any new RADIUS specification MUST NOT introduce new "ad hoc" cryptographic primitives to authenticate packets as was done with the Request / Response Authenticator, or to obfuscate attributes as was done with User-Password and Tunnel-Password.  That is, RADIUS-specific cryptographic methods existing as of the publication of this document can continue to be used for historical compatibility.  However, all new cryptographic work in the RADIUS protocol is forbidden.

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

The intent is for CUI to leak as little information as possible, and ideally be different for every session.  However, business agreements, legal requirements, etc. may mandate different behavior.  The intention of this section is not to mandate complete CUI privacy, but instead to clarify the trade-offs between CUI privacy and business realities.

## User-Password Visibility

The design of RADIUS means that when proxies receive Access-Request packets, the clear-text contents of the User-Password attribute are visible to the proxy.  Despite various claims to the contrary, the User-Password attribute is never sent "in the clear" over the network.  Instead, the password is protected by TLS (RADIUS/TLS) or via the obfuscation methods defined in {{RFC2865}} Section 5.2.  However, the nature of RADIUS means that each proxy must first undo the password obfuscation of {{RFC2865}}, and then re-do it when sending the outbound packet.  As such, the proxy has the clear-text password visible to it, and stored in its application memory.

It is therefore possible for every intermediate proxy to snoop and record all user identities and passwords which they see.  This exposure is most problematic when the proxies are administered by an organization other than the one which operates the home server.  Even when all of the proxies are operated by the same organization, the existence of clear-text passwords on multiple machines is a security risk.

It is therefore NOT RECOMMENDED for organizations to send the User-Password attribute in packets which are sent outside of the local organization.  If RADIUS proxying is necessary, another authentication method SHOULD be used.

Client and server implementations SHOULD use programming techniques to securely wipe passwords from memory when they are no longer needed.

Organizations MAY still use User-Password attributes within their own systems, for reasons which we will explain in the next section.

## Minimize the use of Proxies

The design of RADIUS means that even when RADIUS/TLS is used, every intermediate proxy has access to all of the information in the packet.  The only way to secure the network from such observers is to minimize the use of proxies.

Where it is still necessary to use intermediate proxies such as with eduroam {{EDUROAM}} and OpenRoaming {{OPENROAMING}}, it is RECOMMENDED to use EAP instead of PAP, CHAP, or MS-CHAP.  If passwords are used, they can be can be protected from being seen by proxies via TLS-based EAP methods such as EAP-TTLS or PEAP.  Passwords can also be omitted entirely from being sent over the network, as with EAP-TLS {{?RFC9190}} or EAP-pwd {{?RFC5931}}.

## Password Visibility and Storage

An attacker may choose to ignore the wire protocol entirely, and therefore bypass all of the issues described earlier in this document.  An attacker could instead focus on a database which holds user credentials such as account names and passwords.  At the time of this writing, databases such as {{PWNED}} claim to have records of over twelve billion user accounts which have been compromised.  Such databases are therefore highly sought-after targets.

The attack discussed in this section is dependent on vulnerabilities with the credential database, and does not assume an attacker can see or modify RADIUS traffic.  As a result, this attack applies equally well when TTLS, PEAP, or RADIUS/TLS are used.  The success of the attack depends only on how the credentials are stored in the database.  Since the choice of authentication method affects the way credentials are stored in the database, the security of that dependency needs to be discussed and explained.

Some organizations may desire to increase the security of their network by avoiding PAP, and using CHAP or MS-CHAP, instead.  These attempts are largely misguided.  If simple password-based methods must be used, in almost all situations, the security of the network as a whole is increased by using PAP in preference to CHAP or MS-CHAP.  The reason is found through a simple risk analysis, which we explain in more detail in the next section.

### PAP Security Analysis

When PAP is used, the RADIUS server obtains a clear-text password from the user, and compares that password to credentials which have been stored in a user database.   The credentials stored in the database can be salted and/or hashed in a form is commonly referred to as being in "crypt"ed form.  The RADIUS server takes the input clear-text password, performs the same "crypt" transformation, and the two "crypt"ed passwords are compared.

Any compromise the RADIUS server will result in that clear-text password leaking.  However, in most cases, the clear-text password is available only in the memory of the RADIUS server application, and only for a short period of time.  An attacker who desires to obtain passwords for all users would have to wait for all users to log in, which can take a substantial amount of time.  During that time, an administrator may discover the breach, and resolve the issue.

In addition with PAP, the credentials in the database are stored securely at all times (presuming that the administrator only stores "crypt"ed credentials).  Any compromise of the database results in the disclosure of minimal information to an attacker.  That is, the attacker cannot easily obtain the clear-text passwords from compromising the database.

The result is that the user passwords are visible in clear-text only for a short time, and then only on the RADIUS server.  The security of this system is not as good as seen with EAP-pwd {{?RFC5931}} for example, but it is not terrible.

While the obfuscation method used for the User-Password attribute has not been shown to be insecure, it is not known to be secure.  The obfuscation method depends on calculating MD5(secret + Request Authenticator), which has a few helpful properties for an attacker.  The cost of brute-forcing short secrets is not large, [](#cracking) discusses that cost in detail.  Even for longer secrets which are humanly generated, the MD5 state for hashing the secret can be pre-calculated and stored on disk.  This process is relatively inexpensive, even for billions of possible shared secrets.  The Request Authenticator can then be added to each pre-calculated state via brute-force, and compared to the obfuscated User-Password data.

The MD5 digest is 16 octets long, and many passwords are shorter than that.  This difference means that the final octets of the digest are placed into the User-Password attribute without modificaiton.  The result is that a brute-force attack does not need to decode the User-Password and see if the decoded password "looks reasonable".  Instead, the attacker simply needs to compare the final octets of the calculated digest with the final octets of the User-Password attribute.  The result is an extremely high probability signal that the guessed secret is correct.

The only protection from this attack is to ensure that the secret is long, and derived from a cryptographically strong pseudo-random number generator.  {#shared-secrets} discusses these issues in more detail.

### CHAP and MS-CHAP Password Storage

In contrast, when CHAP or MS-CHAP is used, those methods do not expose a clear-text password to the RADIUS server, but instead a hashed transformation of it.  That hash output is in theory secure even if an attacker can observe it.  While CHAP is believed to be secure, MS-CHAP is not, as we will see below in ([](#ms-chap)).  For the purposes of this section, we will focus on the construct of "hashed passwords", and will ignore any attacks specific to MS-CHAP.  We will also note that EAP-MD5 {{?RFC3748, Section 5.4}} is essentially CHAP, and has the same security analysis.

The hash transformations for CHAP and MS-CHAP depend on a random challenge.  The intent was to increase security, but their construction makes strong requirements on the form in which user credentials are stored.

The process for performing CHAP and MS-CHAP is inverted from the process for PAP.  Using similar terminology as above for illustrative purposes, the "crypt"ed passwords are sent to the server.  The server must obtain the clear-text (or NT hashed) password from the database, and then perform the "crypt" operation on the password from the database. The two "crypt"ed passwords are then compared as was done with PAP.  This inverted process has substantial and negative impacts on security.

When CHAP or MS-CHAP are used, all of credentials are stored as clear-text passwords (or clear-text equivalent) in the database, all of the time.  The database contents might be encrypted, but the decryption keys are necessarily accessible to the application which reads that database.  Any compromise of the application means that the entire database can be immediately read and exfiltrated as a whole.  The attacker then has complete access to all user identities, and all associated clear-text passwords.

### On-the-wire User-Password versus CHAP-Password

There is one more security myth which should be put to rest about PAP versus CHAP.  There is a common belief that CHAP is more secure, because passwords are sent "in the clear" via the User-Password attribute.  This belief is false.

The User-Password attribute is obfuscated when it is sent in an Access-Request packet, using keyed MD5 and the shared secret, as defined in {{RFC2865, Section 5.2}}.  At the time of this writing, no attack better than brute force has been found which allows an attacker to reverse this obfuscation.

There have been claims that it is preferable to use CHAP-Password as it does not "send the password in clear-text".  This claim is likewise false.

The CHAP-Password attribute depends on the hash of a visible Request Authenticator (or CHAP-Challenge) and the users password, while the obfuscated User-Password depends on the same Request Authenticator, and on the RADIUS shared secret.  For an attacker, the difference between the two calculations is minimal.  They can both be attacked with similar amounts of effort.   As a result, any security analysis which makes the claim that "User-Password insecure because it uses MD5" ignores the fact that the CHAP-Password attribute is constructed through substantially similar methods.

### PAP vs CHAP Conclusions

A careful security analyis shows that for all of PAP, CHAP, and MS-CHAP, the RADIUS server must at some point have access to the clear-text version of the password.  As a result, there is minimal difference in risk exposure between the different authentication methods if a RADIUS server is compromised.

However, when PAP is used, the user credentials can be stored securely "at rest" in a database, while such secure storage is impossible with CHAP and MS-CHAP.  There is therefore a substantial difference in risk exposure between the different authentication methods, with PAP offering substantially higher security due to its ability to secure passwords at rest via the "crypt" construct mentioned above.  In contrast, CHAP is highly insecure, as any database compromise results in the immediate exposure of the clear-text passwords for all users.

This difference is shown not just in the {{PWNED}} database, but also in attacks on RADIUS systems {{EXPLOIT}}, where attackers identify a vulnerable RADIUS system and:

> utilized SQL commands to dump the credentials \[T1555\], which contained both cleartext and hashed passwords for user and administrative accounts. 

The attack then proceeded to leverage those passwords:

> Having gained credentials from the RADIUS server, PRC state-sponsored cyber actors used those credentials with custom automated scripts to authenticate to a router via Secure Shell (SSH), execute router commands, and save the output.

This attack is only possible when systems store clear-text passwords.

The result is that when the system as a whole is taken into account, the risk of password compromise is substantially less with PAP than with CHAP or MS-CHAP.  It is therefore RECOMMENDED that administrators use PAP in preference to CHAP or MS-CHAP.  It is also RECOMMENDED that administrators store passwords "at rest" in a secure form (salted, hash), as with the "crypt" format discussed above.

That being said, other authentication methods such as EAP-TLS {{?RFC9190}} and EAP-pwd {{?RFC5931}} do not expose clear-text passwords to the RADIUS server, and therefore can lower the risk of password exposure even more.  It is RECOMMENDED that administrators avoid password-based authentication methods where at all possible.

## MS-CHAP can be reversed {#ms-chap}

MS-CHAP (v1 in {{RFC2433}} and v2 in {{RFC2759}}) has major design flaws, and should not be used outside of a secure tunnel such as with PEAP or TTLS.  As MS-CHAPv1 is less commonly used, the discussion in this section will focus on MS-CHAPv2.

Recent developments demonstrate just how easy it is to attack MS-CHAPv2 exchanges, and obtain the "NT-hash" version of the password ({{SENSEPOST}}).  The attack relies on a vulnerability in the protocol design in {{RFC2759}} Section 8.4.  In that section, the response to the MS-CHAP challenge is calculated via three DES operations, which are based on the 16-octet NT-Hash form of the password.  However, the DES operation requires 7 octet keys, so the 16-octet NT-Hash cannot be divided evenly into the 21 octets of keys required for the DES operation.

The solution in {{RFC2759}} Section 8.4 is to use the first 7 octets of the NT-Hash for the first DES key, the next 7 octets for the second DES key, leaving only 2 octets for the final DES key.  The final DES key is padded with zeros.  This construction means that an attacker who can observe the MS-CHAP2 exchange only needs to perform 2^16 DES operations in order to determine the final 2 octets of the original NT-Hash.

If the attacker has a database which correlates known passwords to NT-Hashes, then those two octets can be used as an index into that database, which returns a subset of candidate hashes.  Those hashes are then checked via brute-force operations to see if they match the original MS-CHAPv2 data.

This process lowers the complexity of cracking MS-CHAP by nearly five orders of magnitude as compared to a brute-force attack.  The attack has been demonstrated using databases which contain tens to hundreds of millions of passwords.  On a consumer-grade machine, the time required for such an attack to succeed is on the order of tens of milliseconds.

While this attack does require a database of known passwords, such databases are easy to find online, or to create locally from generator functions.  Passwords created manually by people are notoriously predictable, and are highly likely to be found in a database of known passwords.  In the extreme case of strong passwords, they will not be found in the database, and the attacker is still required to perform a brute-force dictionary search.

In fact, MS-CHAP has significantly poorer security than PAP when the MS-CHAP data is sent over the network in the clear.  When the MS-CHAP data is not protected by TLS, it is visible to everyone who can observe the RADIUS traffic.  Attackers who can see the MS-CHAP traffic can therefore obtain the underlying NT-Hash with essentially zero effort, as compared to cracking the RADIUS shared secret.  In contrast, the User-Password attribute is obfuscated with data derived from the Request Authenticator and the shared secret, and that method has not been successfully attacked.

Implementors and administrators SHOULD therefore consider MS-CHAP and MS-CHAPv2 to be equivalent in security to sending passwords in the clear, without any encryption or obfuscation.  That is, the User-Password attribute with obfuscation is substantially more secure than MS-CHAP.  MS-CHAP offers little benefit over PAP, and has many drawbacks as discussed here, and in the previous section.

As MS-CHAP can be trivially broken by an observer, this document therefore mandates that MS-CHAP or MS-CHAPv2 authentication data carried in RADIUS MUST NOT be sent in situations where the that data is visible to an observer.  MS-CHAP or MS-CHAPv2 authentication data MUST NOT be sent over RADIUS/UDP or RADIUS/TCP.

As MS-CHAP offers no benefits over PAP, MS-CHAP authentication SHOULD NOT be used even when the transport protocol is protected, as with IPSec or RADIUS over TLS.

Existing RADIUS client implementations SHOULD deprecate the use of MS-CHAP entirely, and SHOULD forbid new configurations from enabling MS-CHAP authentication.  New RADIUS clients MUST NOT implement the attributes used for MS-CHAPv1 and MS-CHAPv2 authentication (MS-CHAP-Challenge and MS-CHAP-Response).

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

> * Do not use RADIUS/UDP or RADIUS/TCP across the wider Internet
>>
>> Exposing user identifiers, device identifiers, and locations is a privacy and security issue.

> * Avoid RADIUS/UDP or RADIUS/TCP in other networks, too.
>>
>> It can take time to upgrade equipment, but the long-term goal is to entirely deprecate RADIUS/UDP.

> * Use strong shared secrets
>>
>> Shared secrets should be generated from a cryptographically strong pseudo-random number generator.  They should contain at least 128 bits of entropy.  Each RADIUS client should have a unique shared secret.

> * Minimize the use of RADIUS proxies.
>>
>> More proxies means more systems which could be compromised, and more systems which can see private or secret data.

> * Do not proxy from secure to insecure transports
>>
>> If user information (credentials or identities) is received over a secure transport (IPSec, RADIUS/TLS, TLS-based EAP method), then proxying the protected data over RADIUS/UDP or RADIUS/TCP degrades security and privacy.

> * Prefer EAP authentication methods to non-EAP methods.
>>
>> EAP authentication methods are better at hiding user credentials from observers.

> * For EAP, use anonymous outer identifiers
>>
>>  There are few reasons to use individual identies for EAP.  Identifying the realm is usually enough.
>>
>> {{RFC7542}} Section 2.4 recommends that "@realm" is preferable to "anonymous@realm", which is in turn preferable to "user@realm".

> * Do not use MS-CHAP outside of TLS-based EAP methods.
>>
>> MS-CHAP can be cracked with minimal effort.

> * Prefer using PAP to CHAP or MS-CHAP.
>>
>> PAP allows for credentials to be stored securely "at rest" in a user database.  CHAP and MS-CHAP do not.

> * Store passwords in "crypt"ed form
>>
>> Where is is necessary to store passwords, use systems such as PBKDF2 ({{?RFC8018}}.

> * Regularly update to the latest cryptographic methods.
>>
>> TLS 1.0 with RC4 was acceptable at one point in time.  It is no longer acceptable.  Similarly, the current cryptographic methods will at some point will be deprecated, and replaced by updated methods.  Upgrading to recent cryptographic methods should be a normal part of operating a RADIUS server.

> * Regularly deprecate older cryptographic methods.
>>
>> Administrators should actively deprecate the use of older cryptographic methods.  If no system is using older methods, then those methods should be disabled or removed entirely.  Leaving old methods enabled makes the server more vulnerable to attacks.

> * Send the minimim amount of information which is needed,.
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

## Historical Considerations

The BlastRADIUS vulnerability is the result of RADIUS security being a low priority for decades.  Even the recommenation of {{?RFC5080, Section 2.2.2}} that all clients add Message-Authenticator to all Access-Request packets was ignored by nearly all implementors.  If that recommendation had been followed, then the BlastRADIUS vulnerability notification would have been little more than "please remember to set the require Message-Authenticator flag on all RADIUS servers."

For MS-CHAP, it has not previously been deprecated for similar reasons, even though it has been proven to be insecure for years.

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

Many thanks to Nadia Heninger and the rest of the BlastRADIUS team for extensive discussions and feedback about the issue.

# Changelog

* 01 - added more discussion of IPSec, and move TLS-PSK to its own document,

* 02 - Added text on Increasing the Security of Insecure Transports

* 03 - add text on CUI.  Add notes on PAP vs CHAP security

* 04 - add text on security of MS-CHAP.  Rearrange and reword many sections for clarity.

* 05 - Rework title to deprecating "insecure practices".  Clarifications based on WG feedback.

* 00 - adoption by WG.

* 01 - review from Bernard Aboba.  Added discussion on accounting, clarified and re-arranged text.  Added discussion of server behavior for missing Message-Authenticator

* 02 - BlastRADIUS updates.

--- back
