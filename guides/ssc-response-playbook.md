# SecurityScorecard Finding Response Playbook

A repeatable workflow for investigating a SecurityScorecard (SSC) finding and
responding to it with evidence gathered by the TPCRM Findings Scanner.

The pattern is vendor-neutral — **look up → decide → prove → submit → verify** —
but this guide fills in SSC's specific labels, paths, and phrasing.

> **Guiding principle: evidence-backed only.** Every response below is meant to
> be *persuasive because it is true*. The tool exists to generate real proof
> (WAF presence, cipher enumeration, backport indicators, edge classification).
> Lead with that proof. Do not assert facts the scan cannot support — it is both
> the honest path and the durable one, since SSC's reviewers tighten over time.

---

## 1. How SSC findings are generated (and why false positives happen)

SSC findings come from **passive, unauthenticated, point-in-time** observation
of hosts attributed to your domain:

- It reads **banners and HTTP headers** (e.g. `Server: Apache/2.4.7`) and infers
  versions/CVEs from the string — it does **not** check the actual patch level.
- It scans **every IP it attributes to you**, which often includes **CDN/WAF
  edge IPs, load balancers, and shared infrastructure** you don't operate.
- It is a **snapshot**: decommissioned hosts, expired DNS, and since-fixed
  issues can linger in a scorecard.

Those three facts are the root of most false positives, and they map directly to
the evidence this tool collects.

---

## 2. The three response paths

| Path | When it applies | SSC submission |
|------|-----------------|----------------|
| **Refute / Dispute** | The finding is wrong: misattributed asset, edge IP that isn't your origin, or the observed fact is incorrect | Dispute flow with supporting evidence |
| **Compensating control** | The finding is real but mitigated (WAF/IDS in front, backported patch, control elsewhere) | "Other resolutions" → "I have a compensating control" |
| **Resolve** | The finding is real and you fixed it (or will) | Mark resolved; re-rate confirms |

> **TODO (real docs):** drop SSC's exact button/option labels and any required
> trigger phrases (e.g. "backported patch", "I have a compensating control")
> here once pulled from the help center, so templates quote them verbatim.

---

## 3. The decision (do this before gathering evidence)

Two questions route every finding:

**Q1 — Is the flagged asset the real thing, or an edge in front of it?**

- Flagged IP is a **managed edge** (CDN/WAF/LB) → the issue is the edge's config
  or isn't your origin at all → lean **Refute (misattribution)**.
- Flagged IP is your **origin** → continue to Q2.

**Q2 — Is the finding wrong, mitigated, or real?**

- **Wrong** → Refute.
- **Real but mitigated** → Compensating control.
- **Real and fixable** → Resolve (and stop arguing).

> The classic trap: claiming "we have a WAF in front" (a compensating control)
> when SSC actually scanned the **WAF edge itself**. That's a refute, not a
> control. The tool's origin/edge classification keeps you on the right path.

---

## 4. Step-by-step

0. **Pin down the finding.** Record the issue type/factor, severity, the exact
   host/IP/port flagged, and the observation date.
1. **Search SSC's support docs** for that finding. Extract: (a) SSC's definition,
   (b) *how it detects* the issue, (c) the accepted resolutions it lists.
2. **Read what they accept** — which of the three paths apply, the required
   phrasing, and any required attachment (e.g. a WAF *signature list*).
3. **Decide** using §3.
4. **Gather evidence** with the tool (see §5).
5. **Map evidence → path** — fill the matching template in §6, leading with the
   strongest evidence bullet.
6. **Submit** via SSC's correct path, attaching the artifacts (and the one thing
   the tool can't produce — your own WAF signature/rule list).
7. **Verify** after SSC re-rates (~48–72h): re-scan and `diff` to confirm the
   finding dropped; keep the artifact as a record.

---

## 5. Finding → command → evidence → path

| SSC finding (typical) | Run | What it proves | Likely path |
|---|---|---|---|
| Service/port exposed, app-security on a CDN IP | `python cli.py scan <host>` | Edge misattribution, or WAF-in-front | Refute / Compensating |
| Weak or deprecated TLS / insecure cipher | `python cli.py scan <host> --cipher` | The exact protocols & ciphers actually offered | Refute or Resolve |
| Outdated server / version-based CVE | `python cli.py scan <host> --backports` | Backport indicators vs. raw version string | Compensating / Refute |
| Missing HSTS / CSP / X-* headers | `python cli.py scan <host> --evidence` | Header present (refute) or genuinely absent | Refute or Resolve |
| TLS certificate expiry | `python cli.py scan <host>` (TLS section) | Real not-after date vs. the claim | Refute or Resolve |
| WAF/IDS in front | `python cli.py scan <host>` (waf_cdn markers) | Proof the protection layer is present & active | Compensating |
| Re-check after fix / re-rate | `python cli.py diff old.json new.json` | Before/after delta | Verify |

---

## 6. Submission templates

Skeletons the scanner's Remediation Narrative can fill. Keep them factual.

**Refute — edge misattribution**
> The flagged IP `<ip>` is a `<provider>` `<edge role>` (`<confidence>`
> confidence), not our origin application server. Evidence: `<rDNS / SAN /
> header markers>`. The reported finding reflects edge configuration or shared
> infrastructure and should not be attributed to our origin asset.

**Compensating control — WAF/IDS in front**
> The endpoint behind `<ip>` sits behind `<provider>` (`<WAF/CDN service>`),
> confirmed by `<evidence markers>`. This WAF/IDS mitigates the reported
> `<finding>`. Attached: our signature/rule list demonstrating coverage for this
> attack class. *(Attachment is required by SSC and supplied by you, not the tool.)*

**Compensating control — backported patch**
> `<software>` on this host reports version `<version>`, but the distribution
> (`<distro>`) ships **backported** security patches; the version string does not
> reflect the patch level. Evidence: `<backport indicators>`. The version-based
> CVE finding is a false positive against the actual patched package.

**Resolve — confirmed and fixed**
> Independent enumeration confirmed `<finding>` (`<evidence>`). We have remediated
> by `<action>`; a follow-up scan (`diff`) shows the issue no longer present.

> **TODO (winning threads):** replace these skeletons with the argument
> structures and phrasings that have actually been accepted, keeping each gated
> on the evidence the tool can produce.

---

## 7. Generic tips (platform defaults & common gotchas)

A growing list of "why this finding looks the way it does" notes.

**TLS — Windows Server enables legacy protocols by default.** Windows (SCHANNEL)
leaves TLS 1.0/1.1 — and on older builds even SSL 3.0 — *available* unless an
admin explicitly disables them. So SSC "supports weak/deprecated TLS" findings
against Windows-hosted origins are usually **real, not false positives**: the
protocol genuinely answers the handshake. Don't try to refute these — confirm
with `--cipher`, then **resolve** by explicitly disabling the old versions
(SCHANNEL `Protocols` registry keys under
`HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols`,
Group Policy, or a helper like IIS Crypto) and re-scan. Note: if the host is
behind a CDN that terminates TLS, the finding may belong to the edge instead —
check the classification first.

**Linux — version strings lie because of backports.** Debian/Ubuntu/RHEL keep
the upstream version number and backport security fixes into it. `Apache/2.4.7`
on Ubuntu may carry patches for CVEs "fixed" in 2.4.40. Use `--backports` to
gather the evidence and submit as a compensating control / false positive.

**CDN/edge IPs aren't your origin.** Findings on a shared Cloudflare/Akamai/
Fastly/CloudFront IP frequently reflect the edge, not your app. Classify first;
many of these are clean refutes.

**Security headers can live at the edge.** A WAF/CDN may add (or strip) headers
the origin doesn't set. If SSC scanned the origin directly, edge-added headers
won't be observed — scan the same surface SSC did.

**Server tokens may be suppressed.** Absence of a version banner isn't proof of
patching, and presence isn't proof of vulnerability. Treat banners as a starting
point, not a verdict.

> **TODO:** extend with more platform defaults as we encounter them.

---

## 8. Worked example (template)

> **TODO:** end-to-end walkthrough — e.g. a weak-cipher finding on a Cloudflare
> IP: classify (edge) → `--cipher` confirms ciphers belong to the edge → refute
> as misattribution, with the scan artifact attached.

---

## Sources

- [How to Resolve Findings on Your SecurityScorecard Rating](https://securityscorecard.com/blog/how-to-resolve-findings-on-your-securityscorecard-rating/)
- [Address issue findings in your Scorecard – Help Center](https://support.securityscorecard.com/hc/en-us/articles/360056026771-Address-issue-findings-in-your-Scorecard)
- [SecurityScorecard: Dispute, Correction, and Appeal](https://securityscorecard.com/blog/securityscorecard-principles-fair-accurate-security-ratings-focus-dispute-correction-appeal)

> Help-center article URLs per finding type will be added to §5 as they're
> pulled, so each row links straight to SSC's own guidance.
