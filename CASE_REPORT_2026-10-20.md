# Case Report: 195-Contract EtherHiding Factory on Polygon

**Analyst:** Himanshu Pandey
**Date:** 2026-10-20
**Chain:** Polygon Mainnet (chain ID 137)
**Classification:** TLP:AMBER

---

## Summary

Wallet `0xCaf2C54E400437da717cF215181B170F65187aBf` has deployed **195 EtherHiding contracts** across 1,038 transactions. **138 contracts** contain decodable C2 values, yielding **68 unique live C2 endpoints** across 9 TLDs plus **2 hardcoded IPs** independently confirmed on VirusTotal as ClickFix/ClearFake infrastructure.

The operator shares the Template A selector set with the previously documented cocova case (`0xb68d1809`, `0xb249cd2d`, `0xe096a091`, `0xf851a440`), indicating a common codebase.


## Active Rotation (2026-10-14 to 2026-10-18)

The operator is currently rotating C2 domains every 1-3 days. The latest writes show a **dual-write pattern**: both the XOR-encrypted contract (`0x4af804`) and the plaintext contract (`0x08207B`) are updated within seconds of each other.

| Date (UTC) | Nonce | Contract | Value |
|---|---|---|---|
| 2026-10-14 09:13 | 271 | 0x4af804 | `year.calvinpre...` (truncated) |
| 2026-10-14 09:58 | 272 | 0x4af804 | `hail.cocova.co` |
| 2026-10-15 09:04 | 273 | 0x4af804 | `hail.cocova.co` |
| 2026-10-15 09:42 | 274 | 0x08207B | `hail.cocova.co` (plaintext) |
| 2026-10-15 09:42 | 275 | 0x4af804 | `hail.cocova.co` |
| 2026-10-17 11:54 | 276 | 0x4af804 | `mug.crossroadc...` (truncated) |
| 2026-10-18 09:36 | 277 | 0x4af804 | `sky.dolcefanta...` (truncated) |
| 2026-10-18 12:53 | 278 | 0x08207B | `sky.dolcefantasia.us` (plaintext) |
| 2026-10-18 12:53 | 279 | 0x4af804 | `sky.dolcefanta...` (truncated) |
| 2026-10-18 12:53 | 280 | 0x08207B | `sky.dolcefantasia.us` (plaintext) |
| 2026-10-18 12:53 | 281 | 0x4af804 | `sky.dolcefanta...` (truncated) |

### New Domains

- `sky.dolcefantasia[.]us` — confirmed from plaintext writes at nonces 278 and 280
- `mug.crossroadc...` — truncated XOR value, likely `.com` or `.cdn` domain (pending verification)

### Dual-Write Pattern

The operator updates both `0x4af804` (XOR-encrypted) and `0x08207B` (plaintext) within seconds of each other. This suggests a single tooling pipeline that writes to both contracts simultaneously, ensuring the malware can resolve the C2 from either storage method.

The most recent write was **2026-10-18 12:53:53 UTC**. The operator is actively maintaining the infrastructure.

### Rotation Cadence

Writes occur every 1-3 days. The 195-contract factory is not static — the operator continuously updates the active resolver contracts while the remaining ~180 contracts sit dormant as reserve capacity.

## Loader Fingerprint Correlation (2026-10-20)

### VirusTotal Captures

22 HTML captures referencing contract `0xB6bC9e1D` were submitted to VirusTotal on 2026-10-08. All 22 reference the primary contract. 13 of 22 also reference the secondary contract `0xf70730A4`. The captures come from four compromised WordPress sites hosting injected SEO-spam pages:

- southeastconsultancy[.]com (9 captures)
- singitwithmj[.]com (9 captures, primary contract only)
- abdulwahabembroidery[.]com (3 captures)
- fortezzaglass[.]com (1 capture)

The observation that `singitwithmj[.]com` carries only the primary contract while the other three carry both suggests two loader builds.

### Observed Exposure

Site `indianrailwayrecruitment[.]in` was reached via search on 2026-10-15. The probable loader carrier (`wp-content/litespeed/js/a97619a149b8a8376ee8b94b23235e9b[.]js`) loaded 4 seconds before an RPC burst. Loader code was not obtained. Outcome: loader executed in the browser; no TDS, lure, or payload delivery observed. Domain flagged by 5 vendors as of 2026-10-02.

### RPC Fallback Fingerprint

**Set B** (this operator, `0xCaf2C54E`):

    1rpc[.]io/matic
    polygon.gateway.tenderly[.]co
    rpc-mainnet.matic.quiknode[.]pro
    polygon-mainnet.public.blastapi[.]io
    rpc.ankr[.]com/polygon
    polygon-bor-rpc.publicnode[.]com
    polygon-public.nodies[.]app
    polygon.drpc[.]org

**Set A** (cocova operator, `0x34c15320`):

    polygon-pokt.nodies[.]app
    polygon-bor-rpc.publicnode[.]com
    polygon.lava[.]build
    polygon.drpc[.]org
    polygon-public.nodies[.]app
    polygon.rpc.subquery[.]network

Only 3 providers overlap. Two distinct operators, shared codebase.

### Detection Rule

Browser DNS (or proxy requests with a page referer) to three or more of the Set B providers within a few minutes. The referer on the RPC requests identifies the compromised site.

### Confidence

The site-to-contract link for the observed exposure rests on the loader fingerprint (medium-high confidence). The direct detonation of `pro-comfort[.]pl` (external, unverified) shows the same contract directly. If verified, this elevates confidence to high.

---

## Confirmed Infection Chain (VirusTotal, 2026-10-19)

    Compromised site: pro-comfort[.]pl
        -> Contract 0xB6bC9e1D0b2fB96Ab7C47E04Cb0BE477410bC1f2
        -> 178[.]16[.]52[.]101 (entry-verifed-cdn[.]codes)
        -> Fake Cloudflare verification
        -> PowerShell irm|iex
        -> 7za + ZIP (password: warden)
        -> helsinki[.]exe (Windows infostealer)
        -> C2: fortuna-qwont[.]club

---

## Hardcoded IPs

    77[.]239[.]114[.]108   (Poland, Intezio Worldwide - ThreatFox IOC #1839449)
    178[.]16[.]52[.]101    (Germany, Omegatech - 16/92 VT detections)

---

## Live C2 Domains (Defanged)

### .beer TLD (30 domains)

    js-server[.]beer
    bigsmart[.]beer
    fontawesome-js-ico[.]beer
    bedcdnset[.]beer
    istile-c-cloud[.]beer
    bacloudserver[.]beer
    vblbs[.]beer
    lasthauszver[.]beer
    web-security[.]beer
    cdn-plugin-js[.]beer
    capcha-cdn-js[.]beer
    ghdnsserverns[.]beer
    nsservclod[.]beer
    vsactivens[.]beer
    cloudcdnginx[.]beer
    viscdnclaud[.]beer
    darndcs-js[.]beer
    bkscndclou[.]beer
    sane-cdn-js[.]beer
    sr-hostes-js[.]beer
    travel-js-ns[.]beer
    lsnsdns[.]beer
    claufancdn[.]beer
    shkcinnc[.]beer
    bhfgtrns-js[.]beer
    srtydnnc[.]beer
    hasmeverdcdn[.]beer
    hftplcnsns[.]beer
    clhfgcomacdn[.]beer
    caffe-store-like[.]beer

### .sbs TLD (13 domains)

    vaer-cdn-3[.]sbs
    image-hoster11[.]sbs
    store-image[.]sbs
    vlns-andb-cdn[.]sbs
    buck-cdns-server[.]sbs
    sdn-inapi-server[.]sbs
    api-server-cdn[.]sbs
    polygon-cnd-stats[.]sbs
    cdn-compress-image[.]sbs
    cdn-2faclov[.]sbs
    winecdn[.]sbs
    virtual-cdncloud[.]sbs
    networksolutionson[.]sbs

### .click TLD (10 domains)

    cloud-safe[.]click
    2fa-cp[.]click
    cdn-server-styles[.]click
    img-cdn-cloud[.]click
    sccdnd-ltyles[.]click
    mcdns-imager[.]click
    vrfimgjs[.]click
    sil-api-js[.]click
    fonts-fontawesome[.]click

### .cfd TLD (5 domains)

    rpc-framework-check[.]cfd
    fonts-fontawesome[.]cfd
    winupdateconf[.]cfd
    panelwork[.]cfd
    hcountry-cdn[.]cfd

### Other TLDs

    chicago-bbq[.]com
    caffe-img[.]com
    cloud-browse[.]codes
    cloud-browser[.]codes
    xdavnode[.]pro
    avscan[.]info
    exp[.]in
    clpuanmeserver[.]shop
    clpcentr[.]world
    dev[.]clpcentr[.]world

### Additional from VirusTotal

    entry-verifed-cdn[.]codes
    idcool[.]codes
    fortuna-qwont[.]club
    pro-comfort[.]pl

---

## Template Generations

| Gen | Bytecode | Count | Status |
|---|---|---|---|
| 1 | 2426 B | 14 | Partially live |
| 2 | 2452 B | 10 | Encrypted (locked) |
| 3 | 2431 B | 159 | Partially live |
| 4 | 1489 B | 12 | Fully active |

---

## Payload Intelligence

- **Payload:** helsinki[.]exe (Windows infostealer)
- **Delivery:** 7za password-protected ZIP (password: warden)
- **Final C2:** fortuna-qwont[.]club
- **User-Agent:** thriaorstiaocs

---

## Attribution

Connected to the **ErrTraffic / Cruciferra** malware-as-a-service ecosystem. Confirmed by eSentire blog reference and ThreatFox tags.

---

## Recommended Actions

1. Block the two hardcoded IPs at network perimeter
2. Block the 68 domains at DNS/proxy layer
3. Hunt for helsinki[.]exe in EDR telemetry
4. Hunt for fortuna-qwont[.]club in network logs
5. Detect PowerShell spawning from explorer.exe
6. Detect 7za.exe extracting password-protected ZIPs in Temp

---

## OPSEC Notes

- All queries were read-only eth_call requests to Alchemy RPC.
- No direct contact with any C2 domain or IP was made.
- TLP:AMBER. Confirm sharing rules before external distribution.

---

*End of report.*
