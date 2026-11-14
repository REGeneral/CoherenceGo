# CoherenceGo
A transport and header coherence checker for bot detection, in Go.

I'd initially intended this to be a simple coherence checker that'd check for coherence across headers. But as I was coding I kept thinking of other signals I could add and decided to just continue on with the project. There's definitely still more signals you could add to this, but with a coherence checker there's only so many signals at the HTTP layer you can add before you start false positiving real users. By all means this is not something you'd put on your site and expect to catch a lot of attackers. You may catch some naive attackers, but competent attackers typically match identically to a browser stack at the network request layer. This is more built as a front runner for catching naive attackers before running more expensive checks, then another anti-bot can handle the more harder to forge signals like browser behaviour, hardware fingerprinting, etc.

## How it works

It takes a file from the corpus directory which has browsers I captured using tls.peet.ws, then scores across three layers separate layers at the network level.

- TLS. Library-default JA4 denylist, per version browser JA4 allowlist, structural extension scoring.
- HTTP/2. Akamai h2 fingerprint, pseudo-header/priority, host+:authority
- Headers. Client-hint coherence, casing accept-language.

## Signals
```
TLS Signals:
1. Library default JA4 denylist. curl, Go net/http, Node fetch/https, Python requests/urllib, Charles, Openbullet2 (RuriLib + SystemNET, h1/1.0/h2) -> +100
2. Per version browser JA4 allowlist, Chrome/Edge 149-157 and Firefox 149-157, with a PSK (0x0029 branch) -> +20 on mismatch
3. Forced h1 contradiction -> +50
4. JA4 extension anomaly list (dead/ancient extensions) -> +15/+25
5. Cross family contamination (Firefox only ext in a Chromium claim, and vice versa) -> +50
6. Impossible fingerprint (both families exclusive extensions in one hello, unknown browser) -> +50

HTTP/2 Signals:
7. Akamai h2 fingerprint hash vs claimed family, gated on h2 -> +20
8. Host + :authority coherence -> +30
9. Priority header structured field validity -> +30

Headers / client hints (Chrome)
10. sec-ch-ua presence (+20) / malformed (+35)
11. sec-ch-ua brand + version coherence vs UA -> +35/+15
12. sec-ch-ua-platform presence (+35) and platform vs UA coherence (+15)
13. sec-ch-ua-mobile presence (+20) and ?1 on desktop (+15)
14. HTTP/1 header casing -> +20
15. HTTP/1 with priority -> +20
16. accept-language missing/* -> +10

Firefox:
17. rv: vs Firefox/ major coherence -> +50
18. casing, priority validility, Host + :authority, accept-language (Firefox variants)
```

## Limitations

This project was calibrated on clean browser captures, one per version, and there's no production false positive data, so thresholds are structural not tuned. The scoring itself is probably all over the place and if you were to use this, you'd want real false positive data to tune the checker against. This project was built to catch naive to intermediate automation, not competent mimics with a real fingerprint and coherent headers. The checker is single request and stateless by design, there's no behavioral or cross request signals. It's also only scoped to Chrome/Firefox/Edge 149-157.

## Usage

You can change what corpus file/point it to your own tls.peet.ws capture on line 817. Run it with:
```
go run main.go
```
and reasoning/score will be outputted to the console.

## Credit

Special thanks to peet, his api service was a life saver for this project!
