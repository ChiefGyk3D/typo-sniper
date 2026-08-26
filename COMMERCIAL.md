# Commercial Licensing

Typo Sniper is dual-licensed.

| | Open source | Commercial |
|---|---|---|
| **Licence** | [GNU AGPL v3](LICENSE) | Negotiated, per organisation |
| **Cost** | Free | Paid |
| **Source disclosure** | Required (see below) | Not required |
| **Suitable for** | Internal use, research, open-source projects | Embedding in a proprietary product or hosted service |

## When the AGPL is enough

Most people never need a commercial licence. The AGPL places no restriction on
**using** Typo Sniper. You can run it, unmodified or modified, to monitor your
own brands, inside a company of any size, commercially, without publishing
anything.

The obligation only arises when you **distribute** the software or **offer
modified versions to others over a network**, and then only for your changes to
Typo Sniper itself — not for unrelated systems that merely consume its output.

Concretely, all of these are fine under the AGPL alone:

- Running scheduled scans for your employer's domains
- Modifying detection logic for internal use and keeping those changes private
- Piping the JSON webhook output into your own closed-source SIEM or ticketing
  system
- Publishing research based on its results

## When you need a commercial licence

You need one if you intend to:

- **Offer Typo Sniper, or a modified version, as a hosted or managed service**
  to third parties without publishing your modifications. AGPL section 13
  requires that remote users of a modified version can obtain its source.
- **Embed it in a proprietary product** you distribute to customers, where
  releasing your product under the AGPL is not acceptable.
- **Redistribute it under different terms** as part of a commercial offering.

A commercial licence removes the source-disclosure requirement. It does not
change the software itself: both licences cover identical code.

## Why AGPL rather than a permissive licence

Typo Sniper is brand-protection tooling, and the most likely commercial use of
it is exactly the case a permissive licence gives away for free: wrapping it in
a hosted monitoring service. Under Apache-2.0 or MIT, a vendor could take this
project, build a paid service on it, and contribute nothing back. Under MPL-2.0
they could do the same as long as they did not modify the original files.

The AGPL closes that gap while leaving ordinary users — the security teams this
is written for — entirely unaffected. If you are running it to protect your own
brands, nothing here applies to you.

## Enquiries

Open a [GitHub issue](https://github.com/ChiefGyk3D/typo-sniper/issues) with the
`licensing` label, or contact the maintainer through the links at
[links.chiefgyk3d.com](https://links.chiefgyk3d.com/socials).

Please include:

- Your organisation and intended use
- Whether you plan to distribute, host, or embed the software
- Expected scale (domains monitored, scan frequency)

## Contributing

Contributions are accepted under the AGPL. Because the project is dual-licensed,
contributors are asked to agree that their contributions may also be offered
under the commercial licence — see [CONTRIBUTING.md](CONTRIBUTING.md).

---

*This page summarises the licensing model in plain terms. The [LICENSE](LICENSE)
file is the binding open-source grant; commercial terms are set out in the
individual agreement. Nothing here is legal advice.*
