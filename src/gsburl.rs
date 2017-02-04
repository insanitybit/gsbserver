use errors::*;

use crypto::digest::Digest;
use crypto::sha2::Sha256;

use std::collections::*;
use regex::*;
use url::*;
use std::ascii::AsciiExt;
use std::borrow::Cow;

// generateHashes returns a set of full hashes for all patterns in the URL.
pub fn generate_hashes(url: &str) -> Result<HashMap<Vec<u8>, String>> {
    let patterns = try!(generate_patterns(url));

    let mut hashes = HashMap::with_capacity(patterns.len());

    for pattern in patterns {
        let hash = hash_from_pattern(&pattern);
        hashes.insert(hash, pattern);
    }
    Ok(hashes)
}

fn hash_from_pattern(pattern: &str) -> Vec<u8> {
    let mut result = vec![0; 32];
    let mut sha256 = Sha256::new();
    sha256.input(pattern.as_bytes());

    sha256.result(&mut result);
    result
}

// generatePatterns returns all possible host-suffix and path-prefix patterns
// for the input URL.
fn generate_patterns(url: &str) -> Result<Vec<String>> {
    let hosts = try!(generate_lookup_hosts(url));

    let paths = try!(generate_lookup_paths(url));

    let mut patterns = vec![];
    for h in &hosts {
        for p in &paths {
            patterns.push(format!("{}{}", h, p));
        }
    }
    Ok(patterns)
}

// isHex reports whether c is a hexadecimal character.
fn is_hex(c: u8) -> bool {
    if (b'0' <= c && c <= b'9') || (b'a' <= c && c <= b'f') || b'A' <= c && c <= b'F' {
        true
    } else {
        false
    }
}
// // unhex converts a hexadecimal character to u8 value in 0..15, inclusive.
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
// escape returns the percent-encoded form of the string s.
fn escape(s: &str) -> String {
    let mut b = Vec::new();
    for c in s.as_bytes() {
        if *c < 0x20 || *c >= 0x7f || *c == b' ' || *c == b'#' || *c == b'%' {
            // Pad the byte so that it is always 2 bytes wide. Hex encode it.
            b.extend_from_slice(format!("%{:02x}", c).as_bytes());
        } else {
            b.push(*c);
        }
    }
    String::from(String::from_utf8_lossy(&b))
}

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
    Ok(escape(&u))
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
fn parse_host(hostish: &str) -> Result<String> {
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
        static ref port_re: Regex = Regex::new(r":\d+$").unwrap();
    }
    // Remove the port if it is there.
    let host = port_re.replace(host, "");

    // Convert internationalized hostnames to IDNA.
    let unescaped_host = unescape(&host);

    let host = if is_unicode(&unescaped_host) {
        match idna::domain_to_ascii(&unescaped_host) {
            Ok(h) => h,
            Err(e) => bail!("Failed to parse domain to ascii {:#?}", e),
        }
    } else {
        host.into_owned()
    };

    lazy_static! {
        static ref dots_re: Regex = Regex::new("[.]+").unwrap();
    }

    let host = dots_re.replace(&host, ".");
    let host = host.trim_matches('.');

    // // Canonicalize IP addresses.
    Ok(parseIPAddress(&host).unwrap_or(host.to_lowercase()))
}

#[derive(Debug)]
struct ParsedUrl {
    pub scheme: String,
    pub host: String,
    pub raw_query: String,
    pub path: String,
}
// // parseURL parses urlStr as a url.URL and reports an error if not possible.
fn parse_url(urlStr: &str) -> Result<ParsedUrl> {
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
    let (rest, query_url) = split(rest, "?", true);
    // var hostish string
    if !rest.starts_with("//") && scheme.is_some() {
        bail!("safebrowsing: invalid path");
    }

    // // Add HTTP as scheme if none.
    let (hostish, rest) = {
        match scheme {
            Some(_) => split(&rest[2..], "/", false),
            None => split(&rest, "/", false),
        }
    };

    let scheme = scheme.unwrap_or("http");

    if hostish == "" {
        bail!("safebrowsing: missing hostname")
    }
    let host = try!(parse_host(hostish));
    // // Format the path.

    let mut p = clean_path(rest);

    if p == "." {
        p = "/".to_owned();
    } else if rest.as_bytes()[rest.as_bytes().len() - 1] == b'/' &&
       p.as_bytes()[p.as_bytes().len() - 1] != b'/' {
        p += "/";
    }
    // parsedURL.Path = p
    // return parsedURL, nil
    Ok(ParsedUrl {
        scheme: scheme.to_owned(),
        host: host,
        raw_query: query_url.to_owned(),
        path: p,
    })
}

// A LazyBuf is a lazily constructed path buffer. (Stolen from go stdlib)
// It supports append, reading previously appended u8s,
// and retrieving the final string. It does not allocate a buffer
// to hold the output until that output diverges from s.
struct LazyBuf<'a> {
    pub s: &'a [u8],
    pub buf: Option<Vec<u8>>,
    pub w: usize,
}

impl<'a> LazyBuf<'a> {
    fn new(s: &'a [u8]) -> LazyBuf {
        LazyBuf {
            s: s,
            buf: None,
            w: 0,
        }
    }

    fn index(&mut self, i: usize) -> u8 {
        if let Some(ref b) = self.buf {
            b[i]
        } else {
            self.s[i]
        }

    }

    fn append(&mut self, c: u8) {
        if let Some(ref mut bf) = self.buf {

            bf[self.w] = c;
            self.w += 1;
            return;
        }
        if self.w < self.s.len() && self.s[self.w] == c {
            self.w += 1;
            return;
        }
        let mut bf = Vec::new();
        bf.extend_from_slice(&self.s[..self.w]);
        self.buf = Some(bf);
    }

    fn to_string(&mut self) -> Result<String> {
        if let Some(ref bf) = self.buf {
            return String::from_utf8(bf[..self.w].to_vec())
                       .chain_err(|| "Failed to convert LazyBuf to string");
        }
        return String::from_utf8(self.s[..self.w].to_vec())
                   .chain_err(|| "Failed to convert LazyBuf to string");
    }
}

// Stole this from the Go stdlib since I really don't want to think hard for this module.
fn clean_path(path: &str) -> String {
    if path.is_empty() {
        return ".".to_owned();
    }

    let rooted = path.as_bytes()[0] == b'/';
    let n = path.len();

    // // Invariants:
    // //	reading from path; r is index of next u8 to process.
    // //	writing to buf; w is index of next u8 to write.
    // //	dotdot is index in buf where .. must stop, either because
    // //		it is the leading slash or it is a leading ../../.. prefix.

    let mut out = LazyBuf::new(path.as_bytes());
    let (mut r, mut dotdot) = (0, 0);

    if rooted {
        out.append(b'/');
        r = 1;
        dotdot = 1;
    }
    let path_bytes = path.as_bytes();
    loop {
        if r >= n {
            break;
        }
        if path_bytes[r] == b'/' {
            r += 1;
        } else if path_bytes[r] == b'.' && (r + 1 == n || path_bytes[r + 1] == b'/') {
            r += 1;
        } else if path_bytes[r] == b'.' && path_bytes[r + 1] == b'.' &&
           (r + 2 == n || path_bytes[r + 2] == b'/') {
            r += 2;

            if out.w > dotdot {
                out.w -= 1;
                let mut w = out.w;
                while out.w > dotdot && out.index(w) != b'/' {
                    out.w -= 1;
                    w = out.w;
                }
            } else if !rooted {
                if out.w > 0 {
                    out.append(b'/');
                    out.append(b'.');
                    out.append(b'.');
                    dotdot = out.w;
                }
            }
        } else {
            if rooted && out.w != 1 || !rooted && out.w != 0 {
                out.append(b'/');
            }
            // copy element
            while r < n && path_bytes[r] != b'/' {
                out.append(path_bytes[r]);

                r += 1;
            }
        }
    }

    // Turn empty string into "."
    if out.w == 0 {
        return ".".to_owned();
    }

    out.to_string().expect("invalid utf8")
}

fn parseIPAddress(iphostname: &str) -> Option<String> {
    // The Windows resolver allows a 4-part dotted decimal IP address to have a
    // space followed by any old rubbish, so long as the total length of the
    // string doesn't get above 15 characters. So, "10.192.95.89 xy" is
    // resolved to 10.192.95.89. If the string length is greater than 15
    // characters, e.g. "10.192.95.89 xy.wildcard.example.com", it will be
    // resolved through DNS.

    lazy_static! {
        static ref trailing_space_re: Regex = Regex::new(r"^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) ").unwrap();
    }

    let mut iphostname = iphostname;

    if iphostname.len() <= 15 {
        let t = trailing_space_re.find(iphostname);

        if let Some(m) = t {
            let substr = &iphostname[m.start()..m.end()];
            let substr = substr.trim();
            iphostname = substr;
        }
    }

    lazy_static! {
        static ref possible_ip_re: Regex = Regex::new(r"^(?i)((?:0x[0-9a-f]+|[0-9\.])+)$").unwrap();
    }

    if !possible_ip_re.is_match(iphostname) {
        return None;
    }
    let parts: Vec<_> = iphostname.split(".").collect();

    if parts.len() > 4 {
        return None;
    }

    // ss := make([]string, len(parts))
    let mut ss = Vec::with_capacity(parts.len());

    for (ix, part) in parts.iter().enumerate() {
        if ix == parts.len() - 1 {
            let cn = canonicalNum(part, 5 - parts.len());
            match cn {
                Some(n) => ss.push(n),
                None => return None,
            }

        } else {
            let cn = canonicalNum(part, 1);
            match cn {
                Some(n) => ss.push(n),
                None => return None,
            }
        }


    }

    Some(ss.join("."))
}
// canonicalNum parses s as an integer and attempts to encode it as a '.'
// separated string where each element is the base-10 encoded value of each u8
// for the corresponding number, starting with the MSself. The result is one that
// is usable as an IP address.
//
// For example:
// 	s:"01234",      n:2  =>  "2.156"
// 	s:"0x10203040", n:4  =>  "16.32.48.64"
fn canonicalNum(s: &str, n: usize) -> Option<String> {
    if n == 0 || n > 4 {
        return None;
    }
    let mut v: u32 = match s.parse() {
        Ok(f) => f,
        Err(_) => return None,
    };

    let mut ss = Vec::new();
    for i in n..0 {
        ss.push((v & 0xff).to_string());
        v >>= 8;
    }

    Some(ss.join("."))
}
// // canonicalURL parses a URL string and returns it as scheme://hostname/path.
// // It strips off fragments and queries.
// fn canonicalURL(u string) (string, error) {
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
fn canonical_host(url: &str) -> Result<String> {
    let parsed_url = try!(parse_url(url));

    Ok(parsed_url.host)
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
    let u = try!(Url::parse(urlStr).chain_err(|| "Failed to parse url"));

    let host_components: Vec<_> = u.host_str().unwrap().split(".").collect();

    let numComponents = if maxHostComponents as usize <= host_components.len() {
        host_components.len() - maxHostComponents as usize
    } else {
        1
    };

    let mut hosts = Vec::new();
    hosts.push(host);
    let mut i = numComponents;
    loop {
        if i >= host_components.len() - 1 {
            break;
        }

        let hjoin = host_components[i as usize..].join(".");
        hosts.push(hjoin);

        i += 1;
    }
    Ok(hosts)
}
// fn canonicalPath(urlStr string) (string, error) {
// 	// Note that this fntion is not used, but remains to ensure that the
// 	// parsedURL.Path output matches C++ implementation.
// 	parsedURL, err := parseURL(urlStr)
// 	if err != nil {
// 		return "", err
// 	}
// 	return parsedURL.Path, nil
// }
//
// generate_lookup_paths returns a list path-prefixes for the input URL.
fn generate_lookup_paths(urlStr: &str) -> Result<Vec<String>> {
    const maxPathComponents: usize = 4;

    let parsedURL = try!(parse_url(urlStr));

    let path = parsedURL.path;

    let mut paths = vec!["/".to_owned()];
    let mut pathComponents = vec![];
    for p in path.split("/") {
        if !p.is_empty() {
            pathComponents.push(p);
        }
    }

    let mut numComponents = pathComponents.len();

    if numComponents > maxPathComponents {
        numComponents = maxPathComponents;
    }

    for i in 1..numComponents {
        paths.push(format!("/{}/", pathComponents[..i].join("/")));
    }

    if path != "/" {
        paths.push(path.clone());
    }
    if parsedURL.raw_query.len() > 0 {
        paths.push(format!("{}?{}", path, parsedURL.raw_query));
    }
    Ok(paths)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_hashes() {
        let url = r"http://google.com/";
        let patterns = generate_patterns(url).unwrap();
        println!("{:#?}", patterns);
        // generate_hashes("https://google.com/").unwrap();
        // generate_hashes("https://192.16.8.2.com/").unwrap();
        // generate_hashes("http://195.127.0.11/%25%32%35/#foo").unwrap();
        // assert_eq!(canonicalize("http://host/%25%32%35").unwrap(),
        //            "http://host/%25");
        // assert_eq!(canonicalize("http://host/%25%32%35%25%32%35").unwrap(),
        //            "http://host/%25%25");
        // // FAILS
        // // assert_eq!(canonicalize("http://host/%2525252525252525").unwrap(),
        // //            "http://host/%25");
        // assert_eq!(canonicalize("http://host/asdf%25%32%35asd").unwrap(),
        //            "http://host/asdf%25asd");
        // // assert_eq!(canonicalize(go).unwrap(),
        // //            "http://host/%25%25%25asd%25%25");
        // assert_eq!(canonicalize("http://www.google.com/").unwrap(),
        //            "http://www.google.com/");
        // assert_eq!(canonicalize("http://%31%36%38%2e%31%38%38%2e%39%39%2e%32%36/%2E%73%65%63%75%72%65/%77%77%77%2E%65%62%61%79%2E%63%6F%6D/").expect("http://%31%36%38%2e%31%38"), "http://168.188.99.26/.secure/www.ebay.com/");
        // assert_eq!(canonicalize("http://195.127.0.11/uploads/%20%20%20%20/.verify/.eBaysecur.\
        //                          unwrap(),updateuserdataxplimnbqmn-xplmvalidateinfoswqpcml.\
        //                          unwrap(),hgplmcx/")
        //                .expect("tp://195.127.0.11/uplo"),
        //            "http://195.127.0.11/uploads/%20%20%20%20/.verify/.eBaysecur.unwrap(),\
        //             updateuserdataxplimnbqmn-xplmvalidateinfoswqpcml.unwrap(),hgplmcx/");
        // assert_eq!(canonicalize("http://host%23.com/%257Ea%2521b%2540c%2523d%2524e%25f%255E00%252611%252A22%252833%252944_55%252B").expect("http://host%23.com/%257Ea%252"), "http://host%23.com/~a!b@c%23d$e%25f^00&11*22(33)44_55+");
        // assert_eq!(canonicalize("http://3279880203/blah").expect("http://3279880203/blah"),
        //            "http://195.127.0.11/blah");
        // assert_eq!(canonicalize("http://www.google.com/blah/..")
        //                .expect("http://www.google.com/blah/.."),
        //            "http://www.google.com/");
        // assert_eq!(canonicalize("www.google.com/").expect("www.google.com/"),
        //            "http://www.google.com/");
        // assert_eq!(canonicalize("www.google.com").expect("www.google.com"),
        //            "http://www.google.com/");
        // assert_eq!(canonicalize("http://www.evil.com/blah#frag")
        //                .expect("http://www.evil.com/blah#frag"),
        //            "http://www.evil.com/blah");
        // assert_eq!(canonicalize("http://www.GOOgle.com/").expect("http://www.GOOgle.com/"),
        //            "http://www.google.com/");
        // assert_eq!(canonicalize("http://www.google.com.../").expect("http://www.google.com.../"),
        //            "http://www.google.com/");
        // assert_eq!(canonicalize("http://www.google.com/foo\tbar\rbaz\n2")
        //                .expect("http://www.google.com/foo\tbar\rbaz\n2"),
        //            "http://www.google.com/foobarbaz2");
        // assert_eq!(canonicalize("http://www.google.com/q?").expect("http://www.google.com/q?"),
        //            "http://www.google.com/q?");
        // assert_eq!(canonicalize("http://www.google.com/q?r?").expect("http://www.google.com/q?r?"),
        //            "http://www.google.com/q?r?");
        // assert_eq!(canonicalize("http://www.google.com/q?r?s")
        //                .expect("http://www.google.com/q?r?s"),
        //            "http://www.google.com/q?r?s");
        // assert_eq!(canonicalize("http://evil.com/foo#bar#baz")
        //                .expect("http://evil.com/foo#bar#baz"),
        //            "http://evil.com/foo");
    }


}
