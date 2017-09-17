# Check DANE TLSA security of an email domain

## Features

- Test the local resover configuration by verifying the validity of
  the root zone DNSKEY and SOA RRSets.

- Test whether DNSSEC is enabled for a given TLD.

- Check whether an email is fully protected (across all of its MX
  hosts) by DANE TLSA records, and whether these match the actual
  certificate chains seen at each IP address of each MX host.

- Perform certificate chain verification at a time offset from the
  current time to ensure that that certificates are not about to
  expire too soon.

A non-zero exit status is returned if any DNS lookups fail or if the
MX records or MX hosts are in an unsigned zone, or if for one of the
MX hosts no associted secure TLSA records are found.  A non-zero exit
status is also returned if any of the SMTP connections fail to establish
a TLS connection or yield a certificat chain that does not match the
TLSA records.

Note that `danecheck` prefers ECDSA to RSA, and only makes one
connection to each IP address, so for hosts that have both ECDSA and RSA
certificates, only the ECDSA certificate will be checked.  Such hosts
are rare, and when their TLSA records are only correct for one of RSA
and ECDSA, it is almost always RSA that is properly configured and ECDSA
that is neglected.  So, for now, testing ECDSA in preference to RSA is
typically a feature, not a bug.

## Synopsis

The `danecheck` command options are as below.

    $ danecheck --help
    danecheck - check for and validate SMTP TLSA records

    Usage: danecheck [-n|--nameserver ADDRESS] [-t|--timeout TIMEOUT]
                     [-r|--tries NUMTRIES] [-H|--helo HELO]
                     [-s|--smtptimeout TIMEOUT] [-l|--linelimit LENGTH]
                     [-R|--reserved] [-D|--down HOSTNAME] [-4|--noipv4] [-6|--ipv6]
                     [-d|--days DAYS] [-e|--eechecks] [DOMAIN]

    Available options:
      -h,--help                Show this help text
      -n,--nameserver ADDRESS  Use nameserver at ADDRESS (default: "127.0.0.1")
      -t,--timeout TIMEOUT     DNS request TIMEOUT (default: 3000 ms)
      -r,--tries NUMTRIES      at most NUMTRIES requests per lookup (default: 6)
      -H,--helo HELO           send specified client HELO name
      -s,--smtptimeout TIMEOUT SMTP TIMEOUT (default: 30000 ms)
      -l,--linelimit LENGTH    Maximum server SMTP response LENGTH (default: 4096)
      -R,--reserved            connect to reserved IP addresses
      -D,--down HOSTNAME       Specify one or more HOSTNAMEs that are down
      -4,--noipv4              disable SMTP via IPv4
      -6,--ipv6                enable SMTP via IPv6
      -d,--days DAYS           check validity at DAYS in the future
      -e,--eechecks            check end-entity (leaf) certificate dates and names
      DOMAIN                   check the specified DOMAIN (default: ".")

    When scanning the root domain, what's checked is secure retrieval of the
    root DNSKEY and SOA RRSets. Similarly, when scanning a top-level domain,
    what's checked is secure retrieval of its DS, DNSKEY and SOA records.
    For all other domains, MX records, address records and TLSA records are
    retrieved and must be DNSSEC signed. Each MX host is expected to have
    TLSA records, an SMTP connection is made to each address of each such MX
    host. A TLS handshake is performed to retrieve the hosts's certificate
    chain which is verified against the DNS TLSA records. If anything is
    unavailable, insecure or wrong, a non-zero exit code is returned.

Reserved addresses include the address blocks from the IANA IPv4 and
IPv6 special purpose address registries:

* [IPv4 Special-Purpose Address Registry](https://www.iana.org/assignments/iana-ipv4-special-registry)
* [IPv6 Special-Purpose Address Registry](https://www.iana.org/assignments/iana-ipv6-special-registry)

these include, for example, the RFC1918 private IPv4 ranges, and
should not appear among the addresses of MX hosts of internet-facing
email domains.  If you're testing a non-public domain on an internal
network, you can use the `-R` option to enable connections to
reserved addresses.

## Building the software

### Prerequisite:  A working GHC + Stack toolchain.

Haskell and stack can be downloaded from the [Haskell platform](https://www.haskell.org/platform/)
website, and are also available as packages for various operating systems.

- Older versions of `stack` can be used to install a more current
  version, which typically installs into `~/.local/bin`.

      $ stack upgrade
      $ stack update

### Developement libraries and headers

Some of the Haskell packages required for `danecheck` depend on
optional C-libraries that may require the installation of additional
OS packages.  Below is a partial list of known optional dependencies
absent on some systems.  There are likely more on some systems.

* libicu for Unicode to ASCII conversion of domain names

### Clone the danecheck Git repository and submodules

The `danecheck` repository uses submodules for some of its dependencies,
the `--recursive` option to `git clone` will automatically clone the
submodules.

    $ git clone --recursive https://github.com/vdukhovni/danecheck
    $ cd danecheck

### Compile and install danecheck

Using a sufficiently recent version of `stack`, in the top-level directory
of the cloned project run

    $ stack install

which will compile and install a copy of the `danecheck` executable in
Stack's default installation directory (typically ~/.local/bin).

## Getting Started

### Choose a working DNSSEC-validating resolver

It is assumed by default that your system has a working DNSSEC-validating
resolver (BIND 9, unbound or similar) running locally and listening on
the loopback interface at UDP and TCP at 127.0.0.1:53.

The system's `/etc/resolv.conf` file is not used.  If you want to
specify a different validating resolver, use the `-n` option to
specify an alternative IP address.  The port number cannot be
changed at present.

### Check that the software and resolver are working

Assuming the installation directory is ~/.local/bin:

    $ PATH=$HOME/.local/bin:$PATH
    $ danecheck || printf "ERROR: root zone record validation failed" >&2

This should output a validated copy of the root zone DNSKEY and SOA
RRSets and not print the ERROR message.  For example (key base64
data abbreviated):

    $ danecheck
    . IN DNSKEY 256 3 8 AwEAAYvxrQOO...L1KLSdmoIYM= ; NoError AD=1
    . IN DNSKEY 257 3 8 AwEAAagAIKlV...QxA+Uk1ihz0= ; NoError AD=1
    . IN DNSKEY 257 3 8 AwEAAaz/tAm8...R1AkUTV74bU= ; NoError AD=1
    . IN SOA a.root-servers.net. nstld@verisign-grs.com. 2017091601 1800 900 604800 86400 ; NoError AD=1

The ` ; NoError AD=1` DNS comments appended to each output line indicates
that the resolver obtained a DNSSEC validated result.  The `.` between the
first and second DNS labels of the SOA contact mailbox field is displayed
as an `@` sign, since some domains have literal `.` characters in the
localpart (first label) of the address.  However, at present, the trailing
`.` is not presently stripped from the domain part of the address.

### Check your TLD

If your domain's ancestor TLD is not DNSSEC signed (still the case for
some ccTLD domains), then DNSSEC will not be used for your domain either,
except from resolvers that have configured a custom trust-anchor for
your domain or one if its ancestor domains.  When checking the DNSSEC
status of a TLD `danecheck` outputs its DS, DNSKEY and SOA RRsets.
For example:

    $ danecheck org
    org. IN DS 9795 7 1 364dfab3daf2...766ddaa24982 ; NoError AD=1
    org. IN DS 9795 7 2 3922b31b6f3a...891bfe7ff8e5 ; NoError AD=1
    org. IN DNSKEY 256 3 7 AwEAAXxsMmN/...Vb99Wac24Fk7 ; NoError AD=1
    org. IN DNSKEY 256 3 7 AwEAAayiVbuM...xTc1wZtAKVjr ; NoError AD=1
    org. IN DNSKEY 257 3 7 AwEAAZTjbIO5...8ti6MNoJEHU= ; NoError AD=1
    org. IN DNSKEY 257 3 7 AwEAAcMnWBKL...wXCNDXk0kk0= ; NoError AD=1
    org. IN SOA a0.org.afilias-nst.info. noc@afilias-nst.info. 2012659235 1800 900 604800 86400 ; NoError AD=1

## Checking your own domain

With your resolver tested for working root zone security and DNSSEC working for
your TLD, you can proceed to regularly test your own domain.  Example:

    $ domain=openssl.org
    $ danecheck "$domain" || printf "ERROR: DANE security check failed for: %s\n" "$domain"
    openssl.org. IN DS 44671 8 2 30abf6c1b7de...ae7c474f83f9 ; NoError AD=1
    openssl.org. IN DNSKEY 256 3 8 AwEAAaJsnu//...0lJQkbhta8V7 ; NoError AD=1
    openssl.org. IN DNSKEY 257 3 8 AwEAAbxptd2o...BUsIsxlbmYs= ; NoError AD=1
    openssl.org. IN MX 50 mta.openssl.org. ; NoError AD=1
    mta.openssl.org. IN A 194.97.150.230 ; NoError AD=1
    mta.openssl.org. IN AAAA 2001:608:c00:180::1:e6 ; NoError AD=1
    _25._tcp.mta.openssl.org. IN CNAME wildcard._dane.openssl.org. ; NoErr AD=1
    wildcard._dane.openssl.org. IN TLSA 3 1 1 687c07fbe249...b911c93ecaca ; NoError AD=1
      mta.openssl.org[194.97.150.230]: pass: TLSA match: depth = 0, name = openssl.org
        TLS = TLS12 with ECDHE-RSA-AES256GCM-SHA384
        name = *.openssl.org
        name = openssl.org
        depth = 0
          Issuer CommonName = GlobalSign Domain Validation CA - SHA256 - G2
          Issuer Organization = GlobalSign nv-sa
          notBefore = 2014-10-09T20:29:00Z
          notAfter = 2017-11-12T17:14:05Z
          Subject CommonName = *.openssl.org
          pkey sha256 [matched] <- 3 1 1 687c07fbe249...b911c93ecaca
        depth = 1
          Issuer CommonName = GlobalSign Root CA
          Issuer Organization = GlobalSign nv-sa
          notBefore = 2014-02-20T10:00:00Z
          notAfter = 2024-02-20T10:00:00Z
          Subject CommonName = GlobalSign Domain Validation CA - SHA256 - G2
          Subject Organization = GlobalSign nv-sa
          pkey sha256 [nomatch] <- 2 1 1 3cbd7f4d30c4...20726c7130a6c

If the exit code indicates failure you should check the output for:

* DNS Failures
  - Any failed DNS queries (not `NoError` or `NODATA`) or insecure answers (`AD=0`)
  - Non-existent MX hosts or TLSA records
* SMTP failures
  - Failures to connect to an MX host at one or more of its IP addresses
  - Rejected or timed-out SMTP commands
  - Lack of STARTTLS support
  - Failure to complete the TLS handshake
* Chain verification failures
  - Failure to find matching TLSA records
  - Name check failure with DANE-TA(2) TLSA records
  - Certificate expiration with DANE-TA(2) TLSA records

## Skipping out-of-service MX hosts

If some of your MX hosts are down, and you want to verify the certificate
chains of only the remaining hosts, you can specify the `--down` option
one or more times to skip SMTP tests for those hosts, their DNS security
(including presence of TLSA records) will still be tested and will be
required for the overall check to succeed.  In the example below, the host
`bh.nic.cz` is down and is skipped, allowing the overall check to succeed.

    $ danecheck --down bh.nic.cz cznic.cz; echo $?
    cznic.cz. IN DS 61281 13 2 fac1a7f06c7c...c6d07e7d8ef7 ; NoError AD=1
    cznic.cz. IN DNSKEY 256 3 13 rs6oetkFuqOg...swO3BfKoLw== ; NoError AD=1
    cznic.cz. IN DNSKEY 257 3 13 LM4zvjUgZi2X...TrDzWmmHwQ== ; NoError AD=1
    cznic.cz. IN MX 10 mail.nic.cz. ; NoError AD=1
    cznic.cz. IN MX 15 mx.nic.cz. ; NoError AD=1
    cznic.cz. IN MX 20 bh.nic.cz. ; NoError AD=1
    mail.nic.cz. IN A 217.31.204.67 ; NoError AD=1
    mail.nic.cz. IN AAAA 2001:1488:800:400::400 ; NoError AD=1
    _25._tcp.mail.nic.cz. IN TLSA 3 1 1 4f9736249ab5...6194f5bb2e09 ; NoError AD=1
      mail.nic.cz[217.31.204.67]: pass: TLSA match: depth = 0, name = mail.nic.cz
        TLS = TLS12 with ECDHE-RSA-AES256GCM-SHA384
        name = jabber.nic.cz
        name = lists.nic.cz
        name = mail.nic.cz
        name = nic.cz
        depth = 0
          Issuer CommonName = Let's Encrypt Authority X3
          Issuer Organization = Let's Encrypt
          notBefore = 2017-08-03T13:02:00Z
          notAfter = 2017-11-01T13:02:00Z
          Subject CommonName = mail.nic.cz
          pkey sha256 [matched] <- 3 1 1 4f9736249ab5...6194f5bb2e09
        depth = 1
          Issuer CommonName = DST Root CA X3
          Issuer Organization = Digital Signature Trust Co.
          notBefore = 2016-03-17T16:40:46Z
          notAfter = 2021-03-17T16:40:46Z
          Subject CommonName = Let's Encrypt Authority X3
          Subject Organization = Let's Encrypt
          pkey sha256 [nomatch] <- 2 1 1 60b87575447d...0517616e8a18
    mx.nic.cz. IN A 217.31.58.56 ; NoError AD=1
    mx.nic.cz. IN AAAA 2001:1ab0:7e1e:c574:7a2b:cbff:fe33:7019 ; NoError AD=1
    _25._tcp.mx.nic.cz. IN TLSA 3 1 1 a9205f093637...b519bf47a523 ; NoError AD=1
      mx.nic.cz[217.31.58.56]: pass: TLSA match: depth = 0, name = mx.nic.cz
        TLS = TLS12 with ECDHE-RSA-AES256GCM-SHA384
        name = mx.nic.cz
        depth = 0
          Issuer CommonName = CZ.NIC SHA2 Root Certification Authority
          Issuer Organization = CZ.NIC, z.s.p.o.
          notBefore = 2017-02-13T09:29:27Z
          notAfter = 2019-02-13T09:29:27Z
          Subject CommonName = mx.nic.cz
          Subject Organization = CZ.NIC
          pkey sha256 [matched] <- 3 1 1 a9205f093637...b519bf47a523
        depth = 1
          Issuer CommonName = CZ.NIC SHA2 Root Certification Authority
          Issuer Organization = CZ.NIC, z.s.p.o.
          notBefore = 2016-02-19T13:58:59Z
          notAfter = 2026-02-16T13:58:59Z
          Subject CommonName = CZ.NIC SHA2 Root Certification Authority
          Subject Organization = CZ.NIC, z.s.p.o.
          pkey sha256 [nomatch] <- 2 1 1 eac0fdbe097f...81ab000c2955
    bh.nic.cz. IN A 217.31.204.252 ; NoError AD=1
    bh.nic.cz. IN AAAA ? ; NODATA AD=1
    _25._tcp.bh.nic.cz. IN TLSA 3 1 1 4f9736249ab5...6194f5bb2e09 ; NoError AD=1
    0

## Examples

### STARTTLS not offered

Here STARTTLS is not offered (to at least some SMTP clients), even though
TLSA records are published:

    $ danecheck rnrfunco.net
    rnrfunco.net. IN MX 10 tusk.sgt.com. ; NoError AD=1
    tusk.sgt.com. IN A 204.107.130.104 ; NoError AD=1
    tusk.sgt.com. IN AAAA ? ; NODATA AD=1
    _25._tcp.tusk.sgt.com. IN TLSA 3 0 1 bd60df4cc8c2...50ac0045659f ; NoError AD=1
      tusk.sgt.com[204.107.130.104]: STARTTLS not offered

### No matching TLSA records

Here none of the TLSA record match the certificate chain:

    $ danecheck dipietro.id.au
    dipietro.id.au. IN MX 10 mail.dipietro.id.au. ; NoError AD=1
    mail.dipietro.id.au. IN A 14.203.171.177 ; NoError AD=1
    mail.dipietro.id.au. IN AAAA ? ; NODATA AD=1
    _25._tcp.mail.dipietro.id.au. IN TLSA 3 1 1 7bf7ea3b070b...34e1e0044e6d ; NoError AD=1
      mail.dipietro.id.au[14.203.171.177]: fail: TLSA mismatch
        TLS = TLS12 with ECDHE-RSA-AES256GCM-SHA384
        name = cloud.dipietro.id.au
    name = dipietro.id.au
        name = mail.dipietro.id.au
    name = www.dipietro.id.au
        name = xmpp.dipietro.id.au
        depth = 0
          Issuer CommonName = Let's Encrypt Authority X3
          Issuer Organization = Let's Encrypt
          notBefore = 2017-07-27T01:31:00Z
          notAfter = 2017-10-25T01:31:00Z
          Subject CommonName = dipietro.id.au
          pkey sha256 [nomatch] <- 3 1 1 51955a5a7b2e...7b158b18db73
        depth = 1
          Issuer CommonName = DST Root CA X3
          Issuer Organization = Digital Signature Trust Co.
          notBefore = 2016-03-17T16:40:46Z
          notAfter = 2021-03-17T16:40:46Z
          Subject CommonName = Let's Encrypt Authority X3
          Subject Organization = Let's Encrypt
          pkey sha256 [nomatch] <- 2 1 1 60b87575447d...0517616e8a18

### TLSA Lookups ServFail

Here TLSA record lookups ServFails due to a buggy nameserver.

    $ danecheck truman.edu
    truman.edu. IN DS 52166 5 1 fc1b03d050bf...a69d7ed8676d ; NoError AD=1
    truman.edu. IN DNSKEY 256 3 5 AwEAAdKNi1TB...RSK2WheyT8zF ; NoError AD=1
    truman.edu. IN DNSKEY 257 3 5 AwEAAZianXgr...ZXk7AnTMbHM= ; NoError AD=1
    truman.edu. IN MX 5 barracuda.truman.edu. ; NoError AD=1
    barracuda.truman.edu. IN A 150.243.160.93 ; NoError AD=1
    barracuda.truman.edu. IN AAAA ? ; ServFail AD=0
    _25._tcp.barracuda.truman.edu. IN TLSA ? ; ServFail AD=0
