# Check DANE TLSA security of an email domain

## Features

- Test the local resolver configuration by verifying the validity of
  the root zone DNSKEY and SOA RRSets.

- Test the DNSSEC delegation chain of a given TLD (DS, DNSKEY and
  SOA), or just DNSKEY and SOA when checking the root zone itself.

- Check whether an email domain is fully protected (across all of
  its MX hosts) by DANE TLSA records, and whether these match the
  actual certificate chains seen at each IP address of each MX host.

- Perform certificate chain verification at a time offset from the
  current time to ensure that certificates are not about to expire
  too soon.

A non-zero exit status is returned if any DNS lookups fail or if the
MX records or MX hosts are in an unsigned zone, or if for one of the
MX hosts no associated secure TLSA records are found.  A non-zero exit
status is also returned if any of the attempted SMTP connections fail
to complete a TLS handshake whose certificate chain matches the TLSA
records.

By default `danecheck` makes one TLS connection per IP and offers
the TLS library's full default set of signature algorithms, letting
the server pick.  Hosts that publish both ECDSA and RSA certificates
are uncommon, and when only one is correctly bound to a TLSA record
it is almost always RSA — so testing whichever cert the server
prioritises is usually sufficient.

Where both certificate kinds are in use and you want to probe them
independently, the `--sigalgs` option restricts (and orders) the
signature-algorithm groups offered to the server.  The argument is
a comma-separated, case-insensitive list of named groups drawn from
`rsa`, `ecdsa` and `eddsa`:

* `--sigalgs ecdsa` &nbsp; offer only ECDSA (P-256\/P-384\/P-521 with
  SHA-2)
* `--sigalgs rsa` &nbsp;&nbsp;&nbsp; offer only RSA (RSA-PSS for TLS 1.3,
  RSA-PKCS#1 for TLS 1.2)
* `--sigalgs eddsa` &nbsp; offer only Ed25519 and Ed448
* `--sigalgs ecdsa,rsa` &nbsp;&nbsp; offer ECDSA first, fall back to RSA
* `--sigalgs any` (or omit the option) &nbsp; the TLS library default

Servers that don't support any of the offered algorithms will fail
the TLS handshake, which is the intended diagnostic — it confirms
that the requested cert kind isn't available at that peer.

## Synopsis

For an overview of the `danecheck` command-line interface, run
`danecheck --help`.

When scanning the root domain, what's checked is secure retrieval
of the root DNSKEY and SOA RRSets.  Similarly, when scanning a
top-level domain, what's checked is secure retrieval of its DS,
DNSKEY and SOA records.  For all other domains, MX records, address
records and TLSA records are retrieved and must be DNSSEC signed.

Each MX host is expected to have TLSA records, an SMTP connection
is made to each address of each such MX host (with the '-A' option
connections are also made to MX hosts that don't have DNSSEC-signd
TLSA records).  A TLS handshake is performed to retrieve the
host's certificate chain, which is verified against the DNS TLSA
RRs.  If anything is unavailable, insecure or wrong, a non-zero
exit code is returned.

The '-D' option can be used zero or more  times to skip SMTP
connections to MX hosts that are expected to be down. The '-U'
option inverts the action of the '-D' option, and connects to only
those MX hosts that are specified via the '-D' option (none if no
such hosts are specified).

Some "reserved" MX host addresses are assumed invalid and not tested by
default.  The command will report a non-zero exit status when these are
encountered.  The reserved addresses are the address blocks from the IANA
IPv4 and IPv6 special purpose address registries:

* [IPv4 Special-Purpose Address Registry](https://www.iana.org/assignments/iana-ipv4-special-registry)
* [IPv6 Special-Purpose Address Registry](https://www.iana.org/assignments/iana-ipv6-special-registry)

these include, for example, the RFC1918 private IPv4 ranges, and
should not appear among the addresses of MX hosts of internet-facing
email domains.  If you're testing a non-public domain on an internal
network, you can use the `-R` option to enable connections to
reserved addresses.

## Building the software

### Prerequisite: A working GHC toolchain

`danecheck` is written in Haskell and depends only on libraries
available from [Hackage](https://hackage.haskell.org/); no external
C libraries are required.

`danecheck` is tested against GHC 9.10.3, 9.12.4 and 9.14.1; any of
these will work.  Use whichever your system already provides, or the
most recent one if you're starting fresh.

Some systems have packages for one or more of the supported
compiler versions.  For example:

  - Fedora 43 has `ghc9.10-devel` and `ghc9.12-devel` meta packages
    that can obviate the need for "ghcup", or make it possible to
    build "ghcup" from source.

  - For MacOS `ghcup`, `ghc@9.10` and `ghc@9.12` are available via
    `homebrew`.

Alternatively, you can install the Haskell toolchain via
[`ghcup`](https://www.haskell.org/ghcup/).  Once `ghcup` is
[installed](https://www.haskell.org/ghcup/install/),
fetch GHC and `cabal-install`:

    $ ghcup install ghc 9.12.4
    $ ghcup set     ghc 9.12.4
    $ ghcup install cabal recommended

**Disk space note**: each GHC toolchain installed by `ghcup` is
substantial — a single GHC takes roughly **2.2–3.0 GB** under
`~/.ghcup/ghc/<version>/`.  By comparison the cabal package store
for `danecheck` and its transitive dependencies is around **470 MB**
under `~/.cabal/store/<ghc-version>-<hash>/`.  Plan for around 3 GB
of free space for a fresh single-GHC setup, more if you install
multiple GHC versions.  Old GHC versions can be removed via `ghcup
rm ghc <version>` when no longer needed.

**GHC 9.14.1 dependency bounds**: a couple of `danecheck`'s
transitive dependencies have not yet relaxed their upper bounds to
admit the `base`, `containers` and `time` versions shipped with GHC
9.14.1.  Two install scenarios behave differently:

* **Building from a source checkout** (e.g. after `git clone`):
  the `cabal.project` shipped in this repository already carries
  the necessary `allow-newer: base, containers, time` stanza, and
  Cabal applies it automatically.  Nothing to do.
* **Installing from Hackage with `cabal install danecheck`**:
  Cabal does *not* consult the package's own `cabal.project`
  during a Hackage install.  Pass the override on the command line
  yourself:

        $ cabal install danecheck --allow-newer=base,containers,time

  or add the same line to your own `cabal.project` / cabal config.

GHC 9.10.3 and 9.12.4 build `danecheck` in either scenario without any
workaround.

### Compile and install danecheck

From the top of the source tree:

    $ cabal update
    $ cabal build danecheck
    $ exe=$(cabal -v0 list-bin danecheck)
    $ strip "$exe"
    $ install "$exe" ~/.local/bin    # or any directory on your PATH

For a self-contained install from Hackage (no source checkout
required), `cabal install danecheck` will fetch the released version
and place the binary under the path configured by `cabal`'s
`installdir` setting (typically `~/.cabal/bin`).

## Getting Started

### Choose a working DNSSEC-validating resolver

It is assumed that your system has a working DNSSEC-validating
resolver (BIND 9, unbound or similar) running locally and
listening on the loopback interface at UDP and TCP at
127.0.0.1:53.

By default the system's `/etc/resolv.conf` file is ignored and the
default nameserver list consists of just "127.0.0.1".  If you want
to specify a different validating resolver, use the `-n` option to
select an alternate IP address.  The `/etc/resolv.conf` nameserver
list can be selected via the `-N` option.

### Check that the software and resolver are working

Assuming the installation directory is ~/.local/bin:

    $ PATH=$HOME/.local/bin:$PATH
    $ danecheck || printf "ERROR: root zone record validation failed\n" >&2

This should output a validated copy of the root zone SOA RR and
not print the ERROR message.  For example:

    $ danecheck
    . IN SOA a.root-servers.net. nstld@verisign-grs.com. 2026060900 1800 900 604800 86400 ; NoError AD=1

The trailing `; NoError AD=1` comment on each output line indicates
the rcode and DNSSEC AD bit of the response.  A validated answer
shows `NoError AD=1`; failures or insecure answers (`AD=0`) are
diagnosed in place.

Validated DS and DNSKEY records are not printed: their successful
retrieval is implicit in the SOA line being secure and present.
Only failing or insecure lookups along the validation chain produce
diagnostic output, so the steady-state success case is intentionally
brief.

The `.` between the first and second DNS labels of the SOA contact
mailbox field is displayed as an `@` sign, since some domains have
literal `.` characters in the localpart (first label) of the
address.  The trailing `.` is not stripped from the domain part of
the address.

### Check your TLD

If your domain's ancestor TLD is not DNSSEC signed (still the case
for some ccTLD domains), then DNSSEC will not be used for your
domain either, except from resolvers that have configured a custom
trust-anchor for your domain or one of its ancestor domains.  When
checking the DNSSEC status of a TLD `danecheck` walks the DS,
DNSKEY and SOA records.  As with the root, validated DS and DNSKEY
records are not printed; only the SOA confirmation appears in the
success case:

    $ danecheck org
    org. IN SOA a0.org.afilias-nst.info. hostmaster.donuts.email. 1781006459 7200 900 1209600 3600 ; NoError AD=1

## Checking your own domain

With your resolver tested for working root zone security and DNSSEC working for
your TLD, you can proceed to regularly test your own domain.  Example:

    $ domain=ietf.org
    $ danecheck ietf.org
    ietf.org. IN MX 0 mail2.ietf.org. ; NoError AD=1
    mail2.ietf.org. IN A 166.84.6.31 ; NoError AD=1
    mail2.ietf.org. IN AAAA 2602:f977:800:f7f6::1 ; NoError AD=1
    _25._tcp.mail2.ietf.org. IN TLSA 3 1 1 810e86ff280553ec895b7f35132a3e919f9aa0517b181645492cd56c8bc2e67a ; NoError AD=1
      mail2.ietf.org[166.84.6.31]: pass: TLSA match: depth = 0, name = *.ietf.org
        TLS = TLS1.3 with TLS_CHACHA20_POLY1305_SHA256,X25519,PubKeyALG_EC
        name = *.ietf.org
        depth = 0
          Issuer CommonName = E8
          Issuer Organization = Let's Encrypt
          notBefore = 2026-04-17T08:18:28Z
          notAfter = 2026-07-16T08:18:27Z
          Subject CommonName = *.ietf.org
          pkey sha256 [matched] <- 3 1 1 810e86ff280553ec895b7f35132a3e919f9aa0517b181645492cd56c8bc2e67a
        depth = 1
          Issuer CommonName = ISRG Root X1
          Issuer Organization = Internet Security Research Group
          notBefore = 2024-03-13T00:00:00Z
          notAfter = 2027-03-12T23:59:59Z
          Subject CommonName = E8
          Subject Organization = Let's Encrypt
          pkey sha256 [nomatch] <- 2 1 1 885bf0572252c6741dc9a52f5044487fef2a93b811cdedfad7624cc283b7cdd5
      mail2.ietf.org[2602:f977:800:f7f6::1]: pass: TLSA match: depth = 0, name = *.ietf.org
        TLS = TLS1.3 with TLS_CHACHA20_POLY1305_SHA256,X25519,PubKeyALG_EC
        name = *.ietf.org
        depth = 0
          Issuer CommonName = E8
          Issuer Organization = Let's Encrypt
          notBefore = 2026-04-17T08:18:28Z
          notAfter = 2026-07-16T08:18:27Z
          Subject CommonName = *.ietf.org
          pkey sha256 [matched] <- 3 1 1 810e86ff280553ec895b7f35132a3e919f9aa0517b181645492cd56c8bc2e67a
        depth = 1
          Issuer CommonName = ISRG Root X1
          Issuer Organization = Internet Security Research Group
          notBefore = 2024-03-13T00:00:00Z
          notAfter = 2027-03-12T23:59:59Z
          Subject CommonName = E8
          Subject Organization = Let's Encrypt
          pkey sha256 [nomatch] <- 2 1 1 885bf0572252c6741dc9a52f5044487fef2a93b811cdedfad7624cc283b7cdd5

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

If some of your MX hosts are down and you want to verify the
certificate chains of only the remaining hosts, you can specify
the `--down` (`-D`) option one or more times to skip SMTP tests
for those hosts.  Their DNS security (including presence of TLSA
records) is still tested and is still required for the overall
check to succeed.  Use `--upside-down` (`-U`) to invert the sense
of `-D` and probe *only* the listed hosts, leaving the rest
unchecked.

## Common failure reasons

- Certificates not matching TLSA records
- No SMTP service on a subset of MX host IP addresses
- STARTTLS not offered
- TLSA Lookups ServFail
- Invalid MX hostname (only MX hosts with "LDH" labels are
  considered valid).
- MX target resolving to an IANA special-purpose IPv4 or IPv6
  address (RFC1918 private space, loopback, 6to4 of any of the
  above, etc.) — overridable with `-R` for testing on internal
  networks
