use errors::*;

use std::collections::*;
use regex::*;
use url::*;
use std::ascii::AsciiExt;
use std::borrow::Cow;

// generateHashes returns a set of full hashes for all patterns in the URL.
fn generate_hashes(url: &str) -> Result<HashMap<String, String>> {
    let patterns = try!(generate_patterns(url));
    // hashes := make(map[hashPrefix]string)
    // for _, p := range patterns {
    // 	hashes[hashFromPattern(p)] = p
    // }
    // return hashes, nil
    unimplemented!()
}

// generatePatterns returns all possible host-suffix and path-prefix patterns
// for the input URL.
fn generate_patterns(url: &str) -> Result<Vec<String>> {
    let hosts = try!(generate_lookup_hosts(url));

    // paths, err := generateLookupPaths(url)
    // if err != nil {
    // 	return nil, err
    // }
    // var patterns []string
    // for _, h := range hosts {
    // 	for _, p := range paths {
    // 		patterns = append(patterns, h+p)
    // 	}
    // }
    // return patterns, nil
    unimplemented!()
}

// isHex reports whether c is a hexadecimal character.
fn is_hex(c: u8) -> bool {
    if (b'0' <= c && c <= b'9') || (b'a' <= c && c <= b'f') || b'A' <= c && c <= b'F' {
        true
    } else {
        false
    }
}
// // unhex converts a hexadecimal character to byte value in 0..15, inclusive.
fn unhex(c: u8) -> u8 {
    match c {
        c if {
            b'0' <= c && c <= b'9'
        } => c - b'0',

        c if {
            b'a' <= c && c <= b'f'
        } => c - b'a' + 10,

        c if {
            b'A' <= c && c <= b'F'
        } => c - b'A' + 10,
        _ => 0,
    }
}
// isUnicode reports whether s is a Unicode string.
fn is_unicode(s: &str) -> bool {
    for c in s.bytes() {
        // For legacy reasons, 0x80 is not considered a Unicode character.
        if c > 0x80 {
            return true;
        }
    }
    return false;
}
// // split splits the string s around the delimiter c.
// //
// // Let string s be of the form:
// //	"%s%s%s" % (t, c, u)
// //
// // Then split returns (t, u) if cutc is set, otherwise, it returns (t, c+u).
// // If c does not exist in s, then (s, "") is returned.
fn split<'a>(s: &'a str, c: &str, cutc: bool) -> (&'a str, &'a str) {
    match s.find(c) {
        None => (s, ""),
        Some(ix) if cutc => (&s[..ix], &s[ix + c.len()..]),
        Some(ix) => (&s[..ix], &s[ix..]),
    }
}
// // escape returns the percent-encoded form of the string s.
// func escape(s string) string {
// 	var b bytes.Buffer
// 	for _, c := range []byte(s) {
// 		if c < 0x20 || c >= 0x7f || c == ' ' || c == '#' || c == '%' {
// 			b.WriteString(fmt.Sprintf("%%%02x", c))
// 		} else {
// 			b.WriteByte(c)
// 		}
// 	}
// 	return b.String()
// }
//
// unescape returns the decoded form of a percent-encoded string s.
fn unescape(s: &str) -> String {
    let mut b = Vec::new();
    let mut s = s;
    loop {
        if s.len() == 0 {
            break;
        }
        if s.len() >= 3 && s.as_bytes()[0] == b'%' && is_hex(s.as_bytes()[0]) &&
           is_hex(s.as_bytes()[2]) {
            b.push(unhex(s.as_bytes()[1]) << 4 | unhex(s.as_bytes()[2]));
            s = &s[3..];
        } else {
            b.push(s.as_bytes()[0]);
            s = &s[1..];
        }
    }
    String::from(String::from_utf8_lossy(&b))
}
// recursiveUnescape unescapes the string s recursively until it cannot be
// unescaped anymore. It reports an error if the unescaping process seemed to
// have no end.
fn recursive_unescape(s: &str) -> Result<String> {
    const max_depth: u16 = 1024;
    let mut s = s.to_owned();

    for _ in 0..max_depth {
        let t = unescape(&s);
        if t == s {
            return Ok(s);
        }
        s = t;
    }
    bail!("Hit max recursion")
}
// normalizeEscape performs a recursive unescape and then escapes the string
// exactly once. It reports an error if it was unable to unescape the string.
fn normalize_escape(s: &str) -> Result<String> {
    let u = try!(recursive_unescape(s));

    unimplemented!()
    // escape(u)
}
// getScheme splits the url into (scheme, path) where scheme is the protocol.
// If the scheme cannot be determined ("", url) is returned.
fn get_scheme<'a>(url: &'a str) -> (Option<&'a str>, &'a str) {

    for (i, c) in url.bytes().enumerate() {
        if b'a' <= c && c <= b'z' || b'A' <= c && c <= b'Z' {
            continue;
        } else if b'0' <= c && c <= b'9' || c == b'+' || c == b'-' || c == b'.' {
            if i == 0 {
                return (None, url);
            }
        } else if c == b':' {
            return (Some(&url[..i]), &url[i + 1..]);
        } else {
            return (None, url);
        }
    }

    (None, url)
}

// parseHost parses a string to get host by the stripping the
// username, password, and port.
fn parse_host<'a>(hostish: &'a str) -> Result<&'a str> {
    let host = match hostish.rfind("@") {
        Some(i) => &hostish[i + 1..],
        None => hostish,
    };

    if host.starts_with("[") {
        // Parse an IP-Literal per RFC 3986 and RFC 6874.
        // For example: "[fe80::1] or "[fe80::1%25en0]"
        let i = host.rfind("]");
        if i.is_none() {
            bail!("safebrowsing: missing ']' in host");
        }
    }

    lazy_static! {
        static ref port_re: Regex = Regex::new(":\\d+$").unwrap();
    }
    // Remove the port if it is there.
    let host = port_re.replace(host, "");

    // Convert internationalized hostnames to IDNA.
    let unescaped_host = match host {
        Cow::Borrowed(h) => unescape(h),
        Cow::Owned(h) => unescape(&h),
    };

    let host = if is_unicode(unescaped_host) {
        tryidna.ToASCII(u)
		if err != nil {
			return "", err
		}
    }

    // Remove any superfluous '.' characters in the hostname.
    host = dotsRegexp.ReplaceAllString(host, ".")
	host = strings.Trim(host, ".")
    // Canonicalize IP addresses.
	if iphost := parseIPAddress(host);    iphost != "" {
		host = iphost
	} else {
		host = strings.ToLower(host)
	}
	return host, nil
}
// // parseURL parses urlStr as a url.URL and reports an error if not possible.
fn parse_url(urlStr: &str) -> Result<String> {
    // For legacy reasons, this is a simplified version of the net/url logic.
    //
    // Few cases where net/url was not helpful:
    // 1. URLs are are expected to have no escaped encoding in the host but to
    // be escaped in the path. Safe Browsing allows escaped characters in both.
    // 2. Also it has different behavior with and without a scheme for absolute
    // paths. Safe Browsing test web URLs only; and a scheme is optional.
    // If missing, we assume that it is an "http".
    // 3. We strip off the fragment and the escaped query as they are not
    // required for building patterns for Safe Browsing.

    // let parsedURL = new(url.URL)
    // Remove the URL fragment.
    // Also, we decode and encode the URL.
    // The '#' in a fragment is not friendly to that.
    let (rest, _) = split(urlStr, "#", true);

    // Start by stripping any leading and trailing whitespace.
    let rest = rest.trim();

    // Remove any embedded tabs and CR/LF characters which aren't escaped.
    let rest: String = rest.chars().filter(|b| *b != '\t' || *b != 'r' || *b != '\n').collect();

    let rest = try!(normalize_escape(&rest));

    let (scheme, rest) = get_scheme(&rest);
    // var hostish string

    if !rest.starts_with("//") && scheme.is_some() {
        bail!("safebrowsing: invalid path");
    }
    // // Add HTTP as scheme if none.
    let (hostish, rest) = {
        match scheme {
            Some(_) => split(&rest, "/", false),
            None => split(&rest[2..], "/", false),
        }
    };

    let scheme = scheme.unwrap_or("http");

    if hostish == "" {
        bail!("safebrowsing: missing hostname")
    }
    let host = try!(parse_host(hostish));
    // // Format the path.
    // p := path.Clean(rest)
    // if p == "." {
    // 	p = "/"
    // } else if rest[len(rest)-1] == '/' && p[len(p)-1] != '/' {
    // 	p += "/"
    // }
    // parsedURL.Path = p
    // return parsedURL, nil
    unimplemented!()
}
// func parseIPAddress(iphostname string) string {
// 	// The Windows resolver allows a 4-part dotted decimal IP address to have a
// 	// space followed by any old rubbish, so long as the total length of the
// 	// string doesn't get above 15 characters. So, "10.192.95.89 xy" is
// 	// resolved to 10.192.95.89. If the string length is greater than 15
// 	// characters, e.g. "10.192.95.89 xy.wildcard.example.com", it will be
// 	// resolved through DNS.
// 	if len(iphostname) <= 15 {
// 		match := trailingSpaceRegexp.FindString(iphostname)
// 		if match != "" {
// 			iphostname = strings.TrimSpace(match)
// 		}
// 	}
// 	if !possibleIPRegexp.MatchString(iphostname) {
// 		return ""
// 	}
// 	parts := strings.Split(iphostname, ".")
// 	if len(parts) > 4 {
// 		return ""
// 	}
// 	ss := make([]string, len(parts))
// 	for i, n := range parts {
// 		if i == len(parts)-1 {
// 			ss[i] = canonicalNum(n, 5-len(parts))
// 		} else {
// 			ss[i] = canonicalNum(n, 1)
// 		}
// 		if ss[i] == "" {
// 			return ""
// 		}
// 	}
// 	return strings.Join(ss, ".")
// }
//
// // canonicalNum parses s as an integer and attempts to encode it as a '.'
// // separated string where each element is the base-10 encoded value of each byte
// // for the corresponding number, starting with the MSB. The result is one that
// // is usable as an IP address.
// //
// // For example:
// //	s:"01234",      n:2  =>  "2.156"
// //	s:"0x10203040", n:4  =>  "16.32.48.64"
// func canonicalNum(s string, n int) string {
// 	if n <= 0 || n > 4 {
// 		return ""
// 	}
// 	v, err := strconv.ParseUint(s, 0, 32)
// 	if err != nil {
// 		return ""
// 	}
// 	ss := make([]string, n)
// 	for i := n - 1; i >= 0; i-- {
// 		ss[i] = strconv.Itoa(int(v) & 0xff)
// 		v = v >> 8
// 	}
// 	return strings.Join(ss, ".")
// }
//
// // canonicalURL parses a URL string and returns it as scheme://hostname/path.
// // It strips off fragments and queries.
// func canonicalURL(u string) (string, error) {
// 	parsedURL, err := parseURL(u)
// 	if err != nil {
// 		return "", err
// 	}
// 	// Assemble the URL ourselves to skip encodings from the net/url package.
// 	u = parsedURL.Scheme + "://" + parsedURL.Host
// 	if parsedURL.Path == "" {
// 		return u + "/", nil
// 	}
// 	u += parsedURL.Path
// 	return u, nil
// }
//
fn canonical_host(urlStr: &str) -> Result<String> {
    let parsedURL = try!(parse_url(urlStr));

    unimplemented!()
    // parsedURL.Host
}
// generateLookupHosts returns a list of host-suffixes for the input URL.
fn generate_lookup_hosts(urlStr: &str) -> Result<Vec<String>> {
    // Safe Browsing policy asks to generate lookup hosts for the URL.
    // Those are formed by the domain and also up to 4 hostnames suffixes.
    // The last component or sometimes the pair isn't examined alone,
    // since it's the TLD or country code. The database for TLDs is here:
    // 	https://publicsuffix.org/list/
    //
    // Note that we do not need to be clever about stopping at the "real" TLD.
    // We just check a few extra components regardless. It's not significantly
    // slower on the server side to check some extra hashes. Also the client
    // does not need to keep a database of TLDs.
    const maxHostComponents: u8 = 7;

    let host = try!(canonical_host(urlStr));

    // // handle IPv4 and IPv6 addresses.
    // u, err := url.Parse(urlStr)
    // if err != nil {
    // 	return nil, err
    // }
    // ip := net.ParseIP(strings.Trim(u.Host, "[]"))
    // if ip != nil {
    // 	return []string{u.Host}, nil
    // }
    // hostComponents := strings.Split(host, ".")
    //
    // numComponents := len(hostComponents) - maxHostComponents
    // if numComponents < 1 {
    // 	numComponents = 1
    // }
    //
    // 	hosts := []string{host}
    // 	for i := numComponents; i < len(hostComponents)-1; i++ {
    // 		hosts = append(hosts, strings.Join(hostComponents[i:], "."))
    // 	}
    // 	return hosts, nil
    unimplemented!()
}
// func canonicalPath(urlStr string) (string, error) {
// 	// Note that this function is not used, but remains to ensure that the
// 	// parsedURL.Path output matches C++ implementation.
// 	parsedURL, err := parseURL(urlStr)
// 	if err != nil {
// 		return "", err
// 	}
// 	return parsedURL.Path, nil
// }
//
// // generateLookupPaths returns a list path-prefixes for the input URL.
// func generateLookupPaths(urlStr string) ([]string, error) {
// 	const maxPathComponents = 4
//
// 	parsedURL, err := parseURL(urlStr)
// 	if err != nil {
// 		return nil, err
// 	}
// 	path := parsedURL.Path
//
// 	paths := []string{"/"}
// 	var pathComponents []string
// 	for _, p := range strings.Split(path, "/") {
// 		if p != "" {
// 			pathComponents = append(pathComponents, p)
// 		}
// 	}
//
// 	numComponents := len(pathComponents)
// 	if numComponents > maxPathComponents {
// 		numComponents = maxPathComponents
// 	}
//
// 	for i := 1; i < numComponents; i++ {
// 		paths = append(paths, "/"+strings.Join(pathComponents[:i], "/")+"/")
// 	}
// 	if path != "/" {
// 		paths = append(paths, path)
// 	}
// 	if len(parsedURL.RawQuery) > 0 {
// 		paths = append(paths, path+"?"+parsedURL.RawQuery)
// 	}
// 	return paths, nil
// }

// #[cfg(test)]
// mod tests {
//     use super::*;
//
//     #[test]
//     fn test_generate_hashes() {
//         let url = "https://google.com/stuff/#frag";
//         generate_hashes(url);
//     }
// }
