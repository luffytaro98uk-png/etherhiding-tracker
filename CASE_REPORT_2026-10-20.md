# Case Report: 195-Contract EtherHiding Factory on Polygon

**Analyst:** Himanshu Pandey
**Date:** 2026-10-20
**Chain:** Polygon Mainnet (chain ID 137)
**Classification:** TLP:AMBER

---

## Summary

Wallet `0xCaf2C54E400437da717cF215181B170F65187aBf` has deployed **195 EtherHiding contracts** across 1,038 transactions. **138 contracts** contain decodable C2 values, yielding **68 unique live C2 endpoints** across 9 TLDs plus **2 hardcoded IPs** independently confirmed on VirusTotal as ClickFix/ClearFake infrastructure.

The operator shares the Template A selector set with the previously documented cocova case (`0xb68d1809`, `0xb249cd2d`, `0xe096a091`, `0xf851a440`), indicating a common codebase.

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
