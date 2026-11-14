// Special thanks to peet, his api service was a life saver for this project!
// tls.peet.ws

// I'd initially intended this to be a simple coherence checker that'd check for coherence across headers. But as I was coding I kept thinking of other signals I could add and decided to
// just continue on with the project. There's definitely still more signals you could add to this, but with a coherence checker there's only so many signals at the HTTP layer you can add before you start
// false positiving real users. By all means this is not something you'd put on your site and expect to catch a lot of attackers. You may catch some naive attackers, but competent attackers
// typically match identically to a browser stack at the network request layer. This is more built as a front runner for catching naive attackers before running more expensive checks, then another
// anti-bot can handle the more harder to forge signals like browser behaviour, hardware fingerprinting, etc.

// It is my first time building a coherence checker, so the scoring weights are probably all over the place as a heads up, and my Go coding may not be entirely idiomatic.

// TLS Signals:

// 1. Library default JA4 denylist. curl, Go net/http, Node fetch/https, Python requests/urllib, Charles, Openbullet2 (RuriLib + SystemNET, h1/1.0/h2) -> +100
// 2. Per version browser JA4 allowlist, Chrome/Edge 149-157 and Firefox 149-157, with a PSK (0x0029 branch) -> +20 on mismatch
// 3. Forced h1 contradiction -> +50
// 4. JA4 extension anomaly list (dead/ancient extensions) -> +15/+25
// 5. Cross family contamination (Firefox only ext in a Chromium claim, and vice versa) -> +50
// 6. Impossible fingerprint (both families exclusive extensions in one hello, unknown browser) -> +50

// HTTP/2 Signals:

// 7. Akamai h2 fingerprint hash vs claimed family, gated on h2 -> +20
// 8. Host + :authority coherence -> +30
// 9. Priority header structured field validity -> +30

// Headers / client hints (Chrome)
// 10. sec-ch-ua presence (+20) / malformed (+35)
// 11. sec-ch-ua brand + version coherence vs UA -> +35/+15
// 12. sec-ch-ua-platform presence (+35) and platform vs UA coherence (+15)
// 13. sec-ch-ua-mobile presence (+20) and ?1 on desktop (+15)
// 14. HTTP/1 header casing -> +20
// 15. HTTP/1 with priority -> +20
// 16. accept-language missing/* -> +10

// Firefox:

// 17. rv: vs Firefox/ major coherence -> +50
// 18. casing, priority validility, Host + :authority, accept-language (Firefox variants)

package main

import (
	"encoding/json"
	"fmt"
	"github.com/dunglas/httpsfv"
	"log"
	"os"
	"strconv"
	"strings"
)

type Fingerprint struct {
	HTTP2 HTTP2 `json:"http2"`
	HTTP1 HTTP1 `json:"http1"`
}

type TLSFingerprint struct {
	TLS tlsFP `json:"tls"`
}

type tlsFP struct {
	JA4 string `json:"ja4_r"`
}

type HTTPVersion struct {
	HTTPV string `json:"http_version"`
}

type HTTP2 struct {
	SentFrames []Frame `json:"sent_frames"`
	Akamaifp   string  `json:"akamai_fingerprint_hash"`
}

type HTTP1 struct {
	Headers []string `json:"headers"`
}

type Frame struct {
	FrameType string   `json:"frame_type"`
	Headers   []string `json:"headers"`
}

type BrowserInfo struct {
	Brand          string
	Major          string
	UseChromeScore bool
}

func headersToMap(headers []string) (map[string]string, map[string]string) {
	out := make(map[string]string, len(headers))
	out2 := make(map[string]string, len(headers))
	for _, h := range headers {
		name, value, found := strings.Cut(h, ": ")
		if !found {
			continue
		}
		out[strings.ToLower(name)] = value
		out2[name] = value
	}
	return out, out2
}

func extractBetween(s, left, right string) string {
	i := strings.Index(s, left)
	if i < 0 {
		return ""
	}
	i += len(left)
	j := strings.Index(s[i:], right)
	if j < 0 {
		return ""
	}
	return s[i : i+j]
}

func detectBrowser(ua string) BrowserInfo {
	// Order matters, Edge, Opera, and Samsung Internet can also include Chrome/.
	rules := []struct {
		token          string
		brand          string
		useChromeScore bool
	}{
		{"Firefox/", "Firefox", false},
		{"FxiOS/", "Firefox iOS", false},
		{"EdgiOS/", "Microsoft Edge iOS", false},
		{"CriOS/", "Google Chrome iOS", false},
		{"EdgA/", "Microsoft Edge", true},
		{"Edg/", "Microsoft Edge", true},
		{"OPR/", "Opera", true},
		{"SamsungBrowser/", "Samsung Internet", true},
		{"Chromium/", "Chromium", true},
		{"Chrome/", "Google Chrome", true},
	}

	products := strings.Fields(ua)
	for _, rule := range rules {
		for _, product := range products {
			version, found := strings.CutPrefix(product, rule.token)
			if found {
				major, _, _ := strings.Cut(version, ".")
				return BrowserInfo{rule.brand, major, rule.useChromeScore}
			}
		}
	}

	// Safari reports its browser version in Version/.
	if strings.Contains(ua, "Safari/") {
		for _, product := range products {
			if version, found := strings.CutPrefix(product, "Version/"); found {
				major, _, _ := strings.Cut(version, ".")
				return BrowserInfo{Brand: "Safari", Major: major}
			}
		}
	}

	return BrowserInfo{Brand: "Unknown"}
}

func transportScoring(protvers string, ja4r string, headers map[string]string, akamaifphash string, browser BrowserInfo) (int, []string) {
	var reasons []string
	score := 0

	// Deny-List first

	if ja4r == "t13d2013h1_002f,0035,003c,003d,009c,009d,1301,1302,c009,c00a,c013,c014,c023,c024,c027,c028,c02b,c02c,c02f,c030_0005,000a,000b,000d,0017,0023,002b,002d,0031,0033,ff01_0804,0805,0806,0401,0501,0201,0403,0503,0203,0202,0601,0603" { // curl default JA4
		score += 100
		reasons = append(reasons, "Curl default JA4 - Deny.")
	} else if ja4r == "t13d1311h2_1301,1302,1303,c009,c00a,c013,c014,c02b,c02c,c02f,c030,cca8,cca9_0005,000a,000b,000d,0012,0017,002b,0033,ff01_0804,0403,0807,0805,0806,0401,0501,0601,0503,0603,0201,0203" { // Go net HTTP default JA4
		score += 100
		reasons = append(reasons, "Go Net/HTTP default JA4 - Deny.")
	} else if ja4r == "t13d5911h1_002f,0032,0033,0035,0038,0039,003c,003d,0040,0067,006a,006b,009c,009d,009e,009f,00a2,00a3,00ff,1301,1302,1303,c009,c00a,c013,c014,c023,c024,c027,c028,c02b,c02c,c02f,c030,c050,c051,c052,c053,c056,c057,c05c,c05d,c060,c061,c09c,c09d,c09e,c09f,c0a0,c0a1,c0a2,c0a3,c0ac,c0ad,c0ae,c0af,cca8,cca9,ccaa_000a,000b,000d,0016,0017,0023,002b,002d,0033_0403,0503,0603,0807,0808,0809,080a,080b,0804,0805,0806,0401,0501,0601,0303,0301,0302,0402,0502,0602" { // Node fetch default JA4
		score += 100
		reasons = append(reasons, "Node fetch default JA4 - Deny.")
	} else if ja4r == "t13d5910_002f,0032,0033,0035,0038,0039,003c,003d,0040,0067,006a,006b,009c,009d,009e,009f,00a2,00a3,00ff,1301,1302,1303,c009,c00a,c013,c014,c023,c024,c027,c028,c02b,c02c,c02f,c030,c050,c051,c052,c053,c056,c057,c05c,c05d,c060,c061,c09c,c09d,c09e,c09f,c0a0,c0a1,c0a2,c0a3,c0ac,c0ad,c0ae,c0af,cca8,cca9,ccaa_000a,000b,000d,0016,0017,0023,002b,002d,0033_0403,0503,0603,0807,0808,0809,080a,080b,0804,0805,0806,0401,0501,0601,0303,0301,0302,0402,0502,0602" { // Node HTTPS default JA4
		score += 100
		reasons = append(reasons, "Node HTTPS default JA4 - Deny.")
	} else if ja4r == "t13d1812h1_0067,006b,009e,009f,00ff,1301,1302,1303,c023,c024,c027,c028,c02b,c02c,c02f,c030,cca8,cca9_000a,000b,000d,0015,0016,0017,002b,002d,0031,0033_0403,0503,0603,0807,0808,0809,080a,080b,0804,0805,0806,0401,0501,0601,0303,0301,0302,0402,0502,0602" { // python's requests default JA4
		score += 100
		reasons = append(reasons, "Python's requests default JA4 - Deny.")
	} else if ja4r == "t13d1813h1_0067,006b,009e,009f,00ff,1301,1302,1303,c023,c024,c027,c028,c02b,c02c,c02f,c030,cca8,cca9_000a,000b,000d,0015,0016,0017,0023,002b,002d,0031,0033_0403,0503,0603,0807,0808,0809,080a,080b,0804,0805,0806,0401,0501,0601,0303,0301,0302,0402,0502,0602" { // python urllib default JA4
		score += 100
		reasons = append(reasons, "Python's urllib default JA4 - Deny.")
	} else if ja4r == "t13d1514h1_002f,0035,009c,009d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9_0005,000a,000b,000d,0011,0017,0023,002b,002d,0032,0033,ff01_0403,0503,0603,0807,0808,0804,0805,0806,0809,080a,080b,0401,0501,0601,0402,0303,0301,0302,0203,0201,0202" { // Charles Proxy default JA4
		score += 100
		reasons = append(reasons, "Charles Proxy default JA4 - Deny.")
	} else if ja4r == "t13d2011_002f,0035,003c,003d,009c,009d,1301,1302,c009,c00a,c013,c014,c023,c024,c027,c028,c02b,c02c,c02f,c030_000a,000b,000d,0017,0023,002b,002d,0031,0033,ff01_0804,0805,0806,0401,0501,0201,0403,0503,0203,0202,0601,0603" {
		score += 100
		reasons = append(reasons, "Openbullet2 RuriLib H/1.1 JA4 - Deny.")
	} else if ja4r == "t13d2012_002f,0035,003c,003d,009c,009d,1301,1302,c009,c00a,c013,c014,c023,c024,c027,c028,c02b,c02c,c02f,c030_000a,000b,000d,0017,0023,0029,002b,002d,0031,0033,ff01_0804,0805,0806,0401,0501,0201,0403,0503,0203,0202,0601,0603" {
		score += 100
		reasons = append(reasons, "Openbullet2 RuriLib H/1.0 JA4 - Deny.")
	} else if ja4r == "t13d2013h2_002f,0035,003c,003d,009c,009d,1301,1302,c009,c00a,c013,c014,c023,c024,c027,c028,c02b,c02c,c02f,c030_000a,000b,000d,0017,0023,0029,002b,002d,0031,0033,ff01_0804,0805,0806,0401,0501,0201,0403,0503,0203,0202,0601,0603" {
		score += 100
		reasons = append(reasons, "Openbullet2 SystemNET H/2 JA4 - Deny.")
	} else if ja4r == "t13d2011_002f,0035,003c,003d,009c,009d,1301,1302,c009,c00a,c013,c014,c023,c024,c027,c028,c02b,c02c,c02f,c030_000a,000b,000d,0017,0023,002b,002d,0031,0033,ff01_0804,0805,0806,0401,0501,0201,0403,0503,0203,0202,0601,0603" {
		score += 100
		reasons = append(reasons, "Openbullet2 SystemNET H/1.1 JA4 - Deny.")
	} else if ja4r == "t13d2012_002f,0035,003c,003d,009c,009d,1301,1302,c009,c00a,c013,c014,c023,c024,c027,c028,c02b,c02c,c02f,c030_000a,000b,000d,0017,0023,0029,002b,002d,0031,0033,ff01_0804,0805,0806,0401,0501,0201,0403,0503,0203,0202,0601,0603" {
		score += 100
		reasons = append(reasons, "Openbullet2 SystemNET H/1.0 JA4 - Deny.")
	}

	major, err := strconv.Atoi(browser.Major)
	if err != nil {
		score += 15 // No browser major, suspicious.
		reasons = append(reasons, "No browser major version, suspicious.")
		scoring, ja4reasons := JA4Scoring(ja4r, browser)
		score += scoring
		reasons = append(reasons, ja4reasons...)
		return score, reasons
	}

	switch {
	// 157 - 150 all have the same ja4 raw fingerprint for chrome, under 150 is different. I've only mapped 149 - 157 so anything under that will be
	case (major == 157 || major == 156 || major == 155 || major == 154 || major == 153 || major == 152 || major == 151 || major == 150) && (browser.Brand == "Google Chrome" || browser.Brand == "Chromium" || browser.Brand == "Microsoft Edge"):
		// Check akamai fingerprint hash matches real chrome, gate on h2, h1 does not have an akamai fp.
		if protvers == "h2" {
			if akamaifphash != "52d84b11737d980aef856699f885ca86" {
				score += 20
				reasons = append(reasons, "Akamai FP hash not equal to claimed Chromium version (157-150).")
			}
		}

		// I use JA4 because JA3 includes elliptic curves and eliptic curve point formats. Not only that but the extension order is sensitive, Chromium rotates extension order (RFC 8446) so the JA3 hash isn't
		// a single hash representing a browser version. JA4 sorts the extensions alphabetically which defeats this, in turn, we can use ja4_r as the main TLS fp hash.

		// I actually discovered PSK by accident when I refreshed on tls.peet.ws/api/all and noticed the JA4 hash extension list went up by 1, then I did some research on it and realized
		// if I didn't add this, it'd block real users who have a warm session. I'm still on the newer side of TLS internals, and this was a new one for me. RFC 8446 for anyone who's interested.

		// One thing I've experienced myself using Bogdannfinn's tls-client is websites may key on akamai fingerprint. If they see an unusual amount of requests being sent from a byte-identical
		// TLS/H2 fp they may force a step-up on said Akamai FP. One way I used to avoid this is forcing HTTP/1 on BogdannFinn's tls-client with a byte identical TLS fp. This would get around the
		// step up. The difference I found is that with --disable-http2 on actual chrome 149, there's 16 extensions and it removes 44cd from JA4_c. This gives me the ability to key on this, stopping
		// people who attempt this like myself, and to not false positive real users. A modern browser stack on HTTP/1.1 in itself is suspicious, but if it's not the correct --disable-http2 fingerprint that should be an immediate step-up.
		// However, further testing shows that Firefox has no difference. Firefox has no ALPS equivalent which means we have to treat H/1.* as a step-up. We mark it as a step-up because
		// some real users may use HTTP/1 though it's extremely rare, we do the same for Chromium.

		if strings.Contains(ja4r, ",0029,") { // Check for Pre Shared Key in raw JA4, else check known good ja4 for 150-157
			if ja4r == "t13d1518h1_002f,0035,009c,009d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9_0005,000a,000b,000d,0012,0017,001b,0023,0029,002b,002d,0033,44cd,ca34,fe0d,ff01_0904,0905,0906,0403,0804,0401,0503,0805,0501,0806,0601" {
				score += 50
				reasons = append(reasons, "HTTP/1.* on byte identical h2 Chromium (157-150), step up immediately.")
			} else if ja4r != "t13d1518h2_002f,0035,009c,009d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9_0005,000a,000b,000d,0012,0017,001b,0023,0029,002b,002d,0033,44cd,ca34,fe0d,ff01_0904,0905,0906,0403,0804,0401,0503,0805,0501,0806,0601" {
				scoring, ja4reasons := JA4Scoring(ja4r, browser)
				if scoring == 0 {
					score += 20
					reasons = append(reasons, "JA4 does not match claimed Chromium version (PSK, 157-150).")
				} else {
					score += scoring
					reasons = append(reasons, ja4reasons...)
				}
			}
		} else if ja4r == "t13d1517h1_002f,0035,009c,009d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9_0005,000a,000b,000d,0012,0017,001b,0023,002b,002d,0033,44cd,ca34,fe0d,ff01_0904,0905,0906,0403,0804,0401,0503,0805,0501,0806,0601" {
			score += 50
			reasons = append(reasons, "HTTP/1.* on byte identical h2 Chromium (157-150), step up immediately.")
		} else if ja4r != "t13d1517h2_002f,0035,009c,009d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9_0005,000a,000b,000d,0012,0017,001b,0023,002b,002d,0033,44cd,ca34,fe0d,ff01_0904,0905,0906,0403,0804,0401,0503,0805,0501,0806,0601" {
			scoring, ja4reasons := JA4Scoring(ja4r, browser)
			if scoring == 0 {
				score += 20
				reasons = append(reasons, "JA4 does not match claimed Chromium version (no PSK, 157-150).")
			} else {
				score += scoring
				reasons = append(reasons, ja4reasons...)
			}
		}

	// Chromium 149
	case major == 149 && (browser.Brand == "Google Chrome" || browser.Brand == "Chromium" || browser.Brand == "Microsoft Edge"):
		if protvers == "h2" {
			if akamaifphash != "52d84b11737d980aef856699f885ca86" {
				score += 20
				reasons = append(reasons, "Akamai FP hash not equal to claimed Chromium version (149).")
			}
		}

		if strings.Contains(ja4r, ",0029,") {
			if ja4r == "t13d1518h1_002f,0035,009c,009d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9_0005,000a,000b,000d,0012,0017,001b,0023,0029,002b,002d,0033,44cd,ca34,fe0d,ff01_0403,0804,0401,0503,0805,0501,0806,0601" {
				score += 50
				reasons = append(reasons, "HTTP/1.* on byte identical h2 Chromium (PSK, 149), step up immediately.")
			} else if ja4r != "t13d1518h2_002f,0035,009c,009d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9_0005,000a,000b,000d,0012,0017,001b,0023,0029,002b,002d,0033,44cd,ca34,fe0d,ff01_0403,0804,0401,0503,0805,0501,0806,0601" {
				scoring, ja4reasons := JA4Scoring(ja4r, browser)
				if scoring == 0 {
					score += 20
					reasons = append(reasons, "JA4 does not match claimed Chromium version (PSK, 149).")
				} else {
					score += scoring
					reasons = append(reasons, ja4reasons...)
				}
			}
		} else if ja4r == "t13d1517h1_002f,0035,009c,009d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9_0005,000a,000b,000d,0012,0017,001b,0023,002b,002d,0033,44cd,ca34,fe0d,ff01_0403,0804,0401,0503,0805,0501,0806,0601" {
			score += 50
			reasons = append(reasons, "HTTP/1.* on byte identical h2 Chromium (no PSK, 149).")
		} else if ja4r != "t13d1517h2_002f,0035,009c,009d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9_0005,000a,000b,000d,0012,0017,001b,0023,002b,002d,0033,44cd,ca34,fe0d,ff01_0403,0804,0401,0503,0805,0501,0806,0601" {
			scoring, ja4reasons := JA4Scoring(ja4r, browser)
			if scoring == 0 {
				score += 20
				reasons = append(reasons, "JA4 does not match claimed Chromium version (no PSK, 149).")
			} else {
				score += scoring
				reasons = append(reasons, ja4reasons...)
			}
		}

		// 157 - 154 same JA4 raw fp for FF, 153-151 are the same, as well as 150-149 (haven't gone further down from 149). You may have noticed firefox's extensions don't go up despite PSK
		// being present in the _a part of the JA4. This is because Chromium leaves the empty session_ticket (35) in place and appends pre_shared_key (41), firefox drops session_ticket
	case (major == 157 || major == 156 || major == 155 || major == 154) && browser.Brand == "Firefox":
		// Check akamai fingerprint hash matches real Firefox
		if protvers == "h2" {
			if akamaifphash != "6ea73faa8fc5aac76bded7bd238f6433" {
				score += 20
				reasons = append(reasons, "Akamai FP hash not equal to claimed Firefox version (157-154).")
			}
		}

		if strings.Contains(ja4r, ",0029,") {
			if ja4r == "t13d1517h1_002f,0035,009c,009d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9_0005,000a,000b,000d,0012,0017,001b,001c,0022,0029,002b,002d,0033,fe0d,ff01_0403,0503,0603,0804,0805,0806,0401,0501,0601,0203,0201" {
				score += 50
				reasons = append(reasons, "HTTP/1.* on byte identical Firefox (PSK, 157-154).")
			} else if ja4r != "t13d1517h2_002f,0035,009c,009d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9_0005,000a,000b,000d,0012,0017,001b,001c,0022,0029,002b,002d,0033,fe0d,ff01_0403,0503,0603,0804,0805,0806,0401,0501,0601,0203,0201" {
				scoring, ja4reasons := JA4Scoring(ja4r, browser)
				if scoring == 0 {
					score += 20
					reasons = append(reasons, "JA4 does not match claimed Firefox version (PSK, 157-154)")
				} else {
					score += scoring
					reasons = append(reasons, ja4reasons...)
				}
			}
		} else if ja4r == "t13d1517h1_002f,0035,009c,009d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9_0005,000a,000b,000d,0012,0017,001b,001c,0022,0023,002b,002d,0033,fe0d,ff01_0403,0503,0603,0804,0805,0806,0401,0501,0601,0203,0201" {
			score += 50
			reasons = append(reasons, "HTTP/1.* on byte identical Firefox (no PSK, 157-154), step up immediately.")
		} else if ja4r != "t13d1517h2_002f,0035,009c,009d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9_0005,000a,000b,000d,0012,0017,001b,001c,0022,0023,002b,002d,0033,fe0d,ff01_0403,0503,0603,0804,0805,0806,0401,0501,0601,0203,0201" {
			scoring, ja4reasons := JA4Scoring(ja4r, browser)
			if scoring == 0 {
				score += 20
				reasons = append(reasons, "JA4 does not match claimed Firefox version (no PSK, 157-154)")
			} else {
				score += scoring
				reasons = append(reasons, ja4reasons...)
			}
		}

	case (major == 153 || major == 152 || major == 151) && browser.Brand == "Firefox":
		if protvers == "h2" {
			if akamaifphash != "6ea73faa8fc5aac76bded7bd238f6433" {
				score += 20
				reasons = append(reasons, "Akamai FP hash not equal to claimed Firefox version (153-151)")
			}
		}

		if strings.Contains(ja4r, ",0029,") {
			if ja4r == "t13d1617h1_002f,0035,009c,009d,1301,1302,1303,c00a,c013,c014,c02b,c02c,c02f,c030,cca8,cca9_0005,000a,000b,000d,0012,0017,001b,001c,0022,0029,002b,002d,0033,fe0d,ff01_0403,0503,0603,0804,0805,0806,0401,0501,0601,0203,0201" {
				score += 50
				reasons = append(reasons, "HTTP/1.* on byte identical Firefox (PSK, 153-151), immediate step-up.")
			} else if ja4r != "t13d1617h2_002f,0035,009c,009d,1301,1302,1303,c00a,c013,c014,c02b,c02c,c02f,c030,cca8,cca9_0005,000a,000b,000d,0012,0017,001b,001c,0022,0029,002b,002d,0033,fe0d,ff01_0403,0503,0603,0804,0805,0806,0401,0501,0601,0203,0201" {
				scoring, ja4reasons := JA4Scoring(ja4r, browser)
				if scoring == 0 {
					score += 20
					reasons = append(reasons, "JA4 does not match claimed Firefox version (PSK, 153-151)")
				} else {
					score += scoring
					reasons = append(reasons, ja4reasons...)
				}
			}
		} else if ja4r == "t13d1617h1_002f,0035,009c,009d,1301,1302,1303,c00a,c013,c014,c02b,c02c,c02f,c030,cca8,cca9_0005,000a,000b,000d,0012,0017,001b,001c,0022,0023,002b,002d,0033,fe0d,ff01_0403,0503,0603,0804,0805,0806,0401,0501,0601,0203,0201" {
			score += 50
			reasons = append(reasons, "HTTP/1.* on byte identical Firefox (no PSK, 153-151), immediate step-up.")
		} else if ja4r != "t13d1617h2_002f,0035,009c,009d,1301,1302,1303,c00a,c013,c014,c02b,c02c,c02f,c030,cca8,cca9_0005,000a,000b,000d,0012,0017,001b,001c,0022,0023,002b,002d,0033,fe0d,ff01_0403,0503,0603,0804,0805,0806,0401,0501,0601,0203,0201" {
			scoring, ja4reasons := JA4Scoring(ja4r, browser)
			if scoring == 0 {
				score += 20
				reasons = append(reasons, "JA4 does not match claimed Firefox version (no PSK, 153-151)")
			} else {
				score += scoring
				reasons = append(reasons, ja4reasons...)
			}
		}
	case (major == 150 || major == 149) && browser.Brand == "Firefox":
		if protvers == "h2" {
			if akamaifphash != "6ea73faa8fc5aac76bded7bd238f6433" {
				score += 20
				reasons = append(reasons, "Akamai FP hash not equal to claimed Firefox version (150-149)")
			}
		}

		if strings.Contains(ja4r, ",0029,") {
			if ja4r == "t13d1717h1_002f,0035,009c,009d,1301,1302,1303,c009,c00a,c013,c014,c02b,c02c,c02f,c030,cca8,cca9_0005,000a,000b,000d,0012,0017,001b,001c,0022,0029,002b,002d,0033,fe0d,ff01_0403,0503,0603,0804,0805,0806,0401,0501,0601,0203,0201" {
				score += 50
				reasons = append(reasons, "HTTP/1.* on byte identical Firefox (PSK, 150-149), immediate step-up.")
			} else if ja4r != "t13d1717h2_002f,0035,009c,009d,1301,1302,1303,c009,c00a,c013,c014,c02b,c02c,c02f,c030,cca8,cca9_0005,000a,000b,000d,0012,0017,001b,001c,0022,0029,002b,002d,0033,fe0d,ff01_0403,0503,0603,0804,0805,0806,0401,0501,0601,0203,0201" {
				scoring, ja4reasons := JA4Scoring(ja4r, browser)
				if scoring == 0 {
					score += 20
					reasons = append(reasons, "JA4 does not match claimed Firefox version (PSK, 150-149)")
				} else {
					score += scoring
					reasons = append(reasons, ja4reasons...)
				}
			}
		} else if ja4r == "t13d1717h1_002f,0035,009c,009d,1301,1302,1303,c009,c00a,c013,c014,c02b,c02c,c02f,c030,cca8,cca9_0005,000a,000b,000d,0012,0017,001b,001c,0022,0023,002b,002d,0033,fe0d,ff01_0403,0503,0603,0804,0805,0806,0401,0501,0601,0203,0201" {
			score += 50
			reasons = append(reasons, "HTTP/1.* on byte identical Firefox (no PSK, 150-149), immediate step-up.")
		} else if ja4r != "t13d1717h2_002f,0035,009c,009d,1301,1302,1303,c009,c00a,c013,c014,c02b,c02c,c02f,c030,cca8,cca9_0005,000a,000b,000d,0012,0017,001b,001c,0022,0023,002b,002d,0033,fe0d,ff01_0403,0503,0603,0804,0805,0806,0401,0501,0601,0203,0201" {
			scoring, ja4reasons := JA4Scoring(ja4r, browser)
			if scoring == 0 {
				score += 20
				reasons = append(reasons, "JA4 does not match claimed Firefox version (no PSK, 150-149)")
			} else {
				score += scoring
				reasons = append(reasons, ja4reasons...)
			}
		}
	default:
		scoring, ja4reasons := JA4Scoring(ja4r, browser)
		score += scoring
		reasons = append(reasons, ja4reasons...)
	}

	return score, reasons
}

func JA4Scoring(ja4r string, browser BrowserInfo) (int, []string) {

	// Ancient extensions that no modern browser uses.
	Signals := map[string][2]string{
		"0016": {"15", "encrypt_then_mac, OpenSSL/LibreSSL default. TLS extension no modern browser sends."},
		"0001": {"15", "max_fragement_length, old RFC6066 mechanism, TLS extension no modern browser sends."},
		"0032": {"15", "signature_algorithms_cert, browsers fold cert sig-algs in 13. TLS extension no modern browser sends."},
		"002f": {"15", "certificate_authorities, servers/mTLS. TLS extension no modern browser sends."},
		"0030": {"15", "old_filters, server-side. TLS extension no modern browser sends."},
		"0031": {"15", "post_handshake_auth, some libraries/cURL. TLS extension no modern browser sends."},
		"0011": {"15", "status_request_v2, deprecated multi-OSCP. TLS extension no modern browser sends."},
		"0018": {"15", "token_binding, deprecated. TLS extension no modern browser sends."},
		"3374": {"25", "next_protocol_negotiation, dead since ~2016. Loud signal, ancient extension."},
		"7550": {"25", "channel_id, old google proprietary. Loud signal, ancient extension."},
		"000f": {"25", "heartbeat, heartbleed era. Loud signal, ancient extension."},
		"000e": {"25", "use_srtp, DTLS/WebRTC only. Loud signal, ancient extension."},
		"0002": {"25", "client_certificate_url, never deployed. Loud signal, ancient extension."},
		"0003": {"25", "trusted_ca_keys, RFC 4366/6066, unused. Loud signal, ancient extension."},
		"0004": {"25", "truncated_hmac, deprecated/prohibited by RFC 8447. Loud signal, ancient extension."},
		"0006": {"25", "user_mapping, RFC 4681 never on the public web. Loud signal, ancient extension."},
		"0007": {"25", "client_authz, experimental, never deployed. Loud signal, ancient extension."},
		"0008": {"25", "server_authz, experimental, never deployed. Loud signal, ancient extension."},
		"0009": {"25", "cert_type, abandoned. Loud signal, ancient extension."},
		"000c": {"25", "srp, barely deployed. Loud signal, ancient extension."},
		"0013": {"25", "client_certificate_type, IoT/constrained only. Loud signal, ancient extension."},
		"0014": {"25", "server_certificate_type, constrained only. Loud signal, ancient extension."},
		"0019": {"25", "cached_info, never meaningfully deployed. Loud signal, ancient extension."},
		"0024": {"25", "TLMSP, never on public web. Loud signal, ancient extension."},
		"0025": {"25", "TLMSP_proxying, never used on public web. Loud signal, ancient extension."},
		"0026": {"25", "TLMSP_delegate, never used on public web. Loud signal, ancient extension."},
		"0027": {"25", "supported_ekt_ciphers, DTLS-SRTP/media wrong context for a web ClientHello. Loud signal, ancient extension."},
	}

	// Chrome extensions no other modern browser uses
	ChromeExtensions := map[string][2]string{
		"44cd": {"0", "ALPS, only appears in Chromium from 149-157, never Firefox."},
		"ca34": {"0", "trust-anchors, only appears in Chromium from 149-157, never Firefox."},
	}

	// Firefox extensions no other modern browser uses
	FirefoxExtensions := map[string][2]string{
		"001c": {"0", "record_size_limit, only appears in Firefox from 149-157, never Chromium."},
		"0022": {"0", "delegated_credentials, only apperas in Firefox from 149-157, never Chromium."},
	}

	var reasons []string
	score := 0

	ja4splits := strings.Split(ja4r, "_")
	if len(ja4splits) < 4 {
		return score, append(reasons, "Malformed JA4, could not parse extensions.")
	}

	var chromeReasons, firefoxReasons []string

	browserCheck := false

	// First check for known browser types. If Firefox extensions exist in claimed Chromium browser, immediate step-up.

	if browser.Brand == "Google Chrome" || browser.Brand == "Chromium" || browser.Brand == "Microsoft Edge" || browser.Brand == "Opera" || browser.Brand == "Microsoft Edge iOS" || browser.Brand == "Google Chrome iOS" || browser.Brand == "Samsung Internet" {
		for _, extension := range strings.Split(ja4splits[2], ",") {
			key := strings.TrimSpace(extension)

			if pair, ok := FirefoxExtensions[key]; ok {
				reasons = append(reasons, pair[1])
				score += 50
				browserCheck = true
			}
		}
	}

	// If Chromium extensions exist in claimed Firefox browser, immediate step-up.

	if browser.Brand == "Firefox" || browser.Brand == "Firefox iOS" {
		for _, extension := range strings.Split(ja4splits[2], ",") {
			key := strings.TrimSpace(extension)

			if pair, ok := ChromeExtensions[key]; ok {
				reasons = append(reasons, pair[1])
				score += 50
				browserCheck = true
			}
		}
	}

	// Check no ancient extensions exist, if they do, add to score & reasons.
	for _, extension := range strings.Split(ja4splits[2], ",") {
		extensionlookup := strings.TrimSpace(extension)
		if pair, ok := Signals[extensionlookup]; ok {
			scoring, reason := pair[0], pair[1]
			scorei, err := strconv.Atoi(scoring)
			if err != nil {
				panic(err)
			}
			score += scorei
			reasons = append(reasons, reason)
		}
	}

	// Fallback for unknown browsers. Check firefox extensions and chrome extensions don't exist together, if they do immediate step-up.
	if browserCheck == false {
		for _, extension := range strings.Split(ja4splits[2], ",") {
			key := strings.TrimSpace(extension)

			if pair, ok := ChromeExtensions[key]; ok {
				chromeReasons = append(chromeReasons, pair[1])
			}
			if pair, ok := FirefoxExtensions[key]; ok {
				firefoxReasons = append(firefoxReasons, pair[1])
			}
		}
	}

	if browserCheck == false {
		if len(chromeReasons) > 0 && len(firefoxReasons) > 0 {
			reasons = append(reasons, firefoxReasons...)
			reasons = append(reasons, chromeReasons...)
			score += 50
		}
	}

	// fmt.Println(score)

	return score, reasons
}

func ChromeScoring(headerpres map[string]string, headers map[string]string, version string, browser BrowserInfo) (int, []string) {
	var reasons []string

	score := 0

	ua := headers["user-agent"]

	uav := extractBetween(ua, "Chrome/", ".")

	chua := headers["sec-ch-ua"]

	// Missing sec-ch-ua header, add to score. This assumes that the connection is HTTPS, chromium does not send these client hint clusters if it is HTTP
	if chua == "" {
		score += 20
		reasons = append(reasons, "Sec-Ch-Ua header is missing for Chromium browser, suspicious.")
	} else if items, err := httpsfv.UnmarshalList([]string{chua}); err != nil {
		score += 35
		reasons = append(reasons, "Sec-Ch-Ua header is malformed for Chromium browser, suspicious.")
	} else {
		chromiumMajor := uav // Major from Chrome/ in the UA.
		if browser.Brand == "Chromium" {
			chromiumMajor = browser.Major
		}

		chromiumSeen := false
		chromiumMismatch := false
		productSeen := false
		productMismatch := false

		for _, member := range items {
			item, ok := member.(httpsfv.Item)
			if !ok {
				continue
			}

			brand, _ := item.Value.(string)
			rawVersion, _ := item.Params.Get("v")
			version, _ := rawVersion.(string)
			major, _, _ := strings.Cut(version, ".")

			switch brand {
			case "Chromium":
				chromiumSeen = true
				if major == "" || major != chromiumMajor {
					chromiumMismatch = true
				}
			case browser.Brand:
				productSeen = true
				if major == "" || major != browser.Major {
					productMismatch = true
				}
			}
		}

		if !chromiumSeen || chromiumMismatch {
			score += 35
			reasons = append(reasons, "Major mismatch between Sec-Ch-Ua header and claimed User-Agent, suspicious.")
		}

		if browser.Brand != "Chromium" {
			switch {
			case !productSeen:
				score += 15
				reasons = append(reasons, "Sec-CH-UA is missing the claimed browser brand: "+browser.Brand+", suspicious (possible test version).")
			case productMismatch:
				score += 35
				reasons = append(reasons, "Major mismatch between Sec-Ch-Ua header and claimed User-Agent (Unknown Browser), suspicious.")
			}
		}
	}

	chplatform := headers["sec-ch-ua-platform"]

	// Check if platform client hint exists, if it doesn't flag, if it does go through checks.
	if chplatform == "" {
		score += 35
		reasons = append(reasons, "Sec-Ch-UA-Platform header does not exist for Chromium browser, suspicious.")
	} else if strings.Contains(ua, "Windows NT") && chplatform != "\"Windows\"" {
		score += 15
		reasons = append(reasons, "Claimed Windows user-agent, Sec-Ch-UA-Platform disagrees.")
	} else if (strings.Contains(ua, "Macintosh") || strings.Contains(ua, "Mac OS X")) && chplatform != "\"macOS\"" {
		score += 15
		reasons = append(reasons, "Claimed Macintosh user-agent, Sec-Ch-UA-Platform disagrees.")
	} else if strings.Contains(ua, "Android") && chplatform != "\"Android\"" {
		score += 15
		reasons = append(reasons, "Claimed Android user-agent, Sec-Ch-UA-Platform disagrees.")
	} else if strings.Contains(ua, "CrOS") && chplatform != "\"Chrome OS\"" {
		score += 15
		reasons = append(reasons, "Claimed Chrome OS user-agent, Sec-Ch-UA-Platform disagrees.")
	} else if strings.Contains(ua, "X11; Linux") && chplatform != "\"Linux\"" {
		score += 15
		reasons = append(reasons, "Claimed Linux user-agent, Sec-Ch-UA-Platform disagrees.")
	}

	chmobile := headers["sec-ch-ua-mobile"]

	// Check if mobile client hint exists & is not iPhone. iPhone runs on WebKit, no client hint clusters are provided.
	if chmobile == "" && !strings.Contains(ua, "iPhone") && !strings.Contains(ua, "iPad") && !strings.Contains(ua, "iPod") {
		score += 20
		reasons = append(reasons, "Mobile client hint does not exist while claiming to be Mobile (non-iOS).")
	}

	// Check if client hint mobile is equal to ?1 and is a desktop client, suspicious
	if chmobile == "?1" && (strings.Contains(chplatform, "Windows") || strings.Contains(chplatform, "Chrome OS") || strings.Contains(chplatform, "Linux") || strings.Contains(chplatform, "macOS")) {
		score += 15
		reasons = append(reasons, "Desktop client but mobile client hint claims Mobile, suspicious.")
	}

	// Check H1 header casing. Chromium keeps sec-ch- headers lowercase, while the rest are uppercase on each starting character delimited by -
	if strings.HasPrefix(version, "HTTP/1") {
		for name := range headerpres {
			isSecCH := strings.HasPrefix(strings.ToLower(name), "sec-ch-")
			valid := true

			for _, part := range strings.Split(name, "-") {
				if part == "" {
					valid = false
					break
				}

				first := part[0]
				if isSecCH {
					valid = first >= 'a' && first <= 'z'
				} else {
					valid = first >= 'A' && first <= 'Z'
				}

				if !valid {
					break
				}
			}

			if !valid {
				score += 20
				reasons = append(reasons, "HTTP/1.1 casing is wrong. Chromium must have all headers starting with capitals and only sec-ch headers lowercase.")
			}
		}
	}

	if headers["host"] != "" && headers[":authority"] != "" && version == "h2" {
		score += 30
		reasons = append(reasons, "Genuine browser stacks do not send Host and :authority, by default it's always :authority, no Host header.")
	}

	// Check if priority is present, if so, check that it's not malformed. Priority header cannot go above 7, or below 0, and cannot include letters. Suspicious.
	if version == "h2" {
		if priority := headers["priority"]; priority != "" {
			fields, err := httpsfv.UnmarshalDictionary([]string{priority})
			if err != nil {
				score += 30
				reasons = append(reasons, "HTTP2 protocol, Priority header present but malformed.")
			} else if member, found := fields.Get("u"); found {
				item, isItem := member.(httpsfv.Item)
				urgency, isInt := item.Value.(int64)

				if !isItem || !isInt || urgency < 0 || urgency > 7 {
					score += 30
					reasons = append(reasons, "HTTP2 protocol, Priority header present but malformed.")
				}
			}
		}
	}

	// HTTP/1.1 with Protocol header, suspicious.

	if strings.Contains(version, "HTTP/1") && headers["priority"] != "" {
		score += 20
		reasons = append(reasons, "HTTP/1.1 with Protocol header, suspicious.")
	}

	language := headers["accept-language"]

	// Check if accept-language isn't present, also check if it's equal to *. Suspicious.
	if language == "" || language == "*" {
		score += 10
		reasons = append(reasons, "Accept-Language not present, or contains *, suspicious.")
	}

	return score, reasons
}

// Firefox scoring isn't as in-depth given client hint clusters aren't provided. From my experience, a lot of anti-bots rely on IP scoring more heavily.
// Another note I'll add is weights are more heavy when en-US accept-language header is used given it's the most common bot language from my experience when dealing with these anti-bots.
// Some also gate on en-US, if a site is United States only, seeing zh-CN in accept-language is a flag, and sometimes an outright block.

func FirefoxScoring(headerpres map[string]string, headers map[string]string, protvers string, browser BrowserInfo) (int, []string) {
	var reasons []string

	score := 0

	ua := headers["user-agent"]

	uavfmajor := extractBetween(ua, "rv:", ".")
	uavsmajor := extractBetween(ua, "Firefox/", ".")

	if uavfmajor != uavsmajor {
		score += 50
		reasons = append(reasons, "First and second majors in claimed user-agent are not the same.")
	}

	if strings.HasPrefix(protvers, "HTTP/1") {
		for name := range headerpres {
			valid := true

			for _, part := range strings.Split(name, "-") {
				if part == "" {
					valid = false
					break
				}

				first := part[0]
				valid = first >= 'A' && first <= 'Z'

				if !valid {
					break
				}
			}

			if !valid {
				score += 15
				reasons = append(reasons, "HTTP/1.1 casing is wrong. Firefox must have all headers starting with capitals delimited by -.")
			}
		}
	}

	if protvers == "h2" {
		if priority := headers["priority"]; priority != "" {
			fields, err := httpsfv.UnmarshalDictionary([]string{priority})
			if err != nil {
				score += 15
				reasons = append(reasons, "HTTP2 protocol, Priority header present but malformed.")
			} else if member, found := fields.Get("u"); found {
				item, isItem := member.(httpsfv.Item)
				urgency, isInt := item.Value.(int64)

				if !isItem || !isInt || urgency < 0 || urgency > 7 {
					score += 15
					reasons = append(reasons, "HTTP2 protocol, Priority header present but malformed.")
				}
			}
		}
	}

	if headers["host"] != "" && headers[":authority"] != "" && protvers == "h2" {
		score += 50
		reasons = append(reasons, "Genuine browser stacks do not send Host and :authority, by default it's always :authority, no Host header.")
	}

	if strings.Contains(protvers, "HTTP/1") && headers["priority"] != "" {
		score += 15
		reasons = append(reasons, "HTTP/1.1 with Protocol header, suspicious.")
	}

	language := headers["accept-language"]

	if language == "" || language == "*" {
		score += 10
		reasons = append(reasons, "Accept-Language not present, or contains *, suspicious.")
	}

	return score, reasons
}

func main() {
	// Parse File
	data, err := os.ReadFile("corpus\\browser\\chrome149.json")
	if err != nil {
		panic(err)
	}

	var httpvers HTTPVersion
	err = json.Unmarshal(data, &httpvers)
	if err != nil {
		log.Fatal("Error during Unmarshal(): ", err)
	}
	ProtocolVersion := httpvers.HTTPV

	var fp Fingerprint
	err = json.Unmarshal(data, &fp)
	if err != nil {
		log.Fatal("Error during Unmarshal(): ", err)
	}

	var h map[string]string
	var hpres map[string]string
	// Map Headers

	if ProtocolVersion == "h2" {
		for _, frame := range fp.HTTP2.SentFrames {
			if len(frame.Headers) > 0 {
				h, hpres = headersToMap(frame.Headers)
				break
			}
		}
	}

	if strings.Contains(ProtocolVersion, "HTTP/1") {
		h, hpres = headersToMap(fp.HTTP1.Headers)
	}

	var tls TLSFingerprint
	err = json.Unmarshal(data, &tls)
	if err != nil {
		log.Fatal("Error during Unmarshal(): ", err)
	}

	JA4r := tls.TLS.JA4

	akamaifphash := ""

	if ProtocolVersion == "h2" {
		akamaifphash = fp.HTTP2.Akamaifp
	}

	browser := detectBrowser(h["user-agent"])
	fmt.Println(browser)

	score, reasons := transportScoring(ProtocolVersion, JA4r, h, akamaifphash, browser)

	switch {
	case browser.UseChromeScore: // Check if Chromium
		chromiumscore, chromiumreasons := ChromeScoring(hpres, h, ProtocolVersion, browser)
		score += chromiumscore
		reasons = append(reasons, chromiumreasons...)
	case browser.Brand == "Firefox": // Check if Firefox
		firefoxscore, firefoxreasons := FirefoxScoring(hpres, h, ProtocolVersion, browser)
		score += firefoxscore
		reasons = append(reasons, firefoxreasons...)
	case browser.Brand == "Unknown":
		score += 15 // Unknown browser, suspicious
		reasons = append(reasons, "Unknown browser, suspicious.")
	}

	fmt.Println(score)
	fmt.Println(reasons)

}
