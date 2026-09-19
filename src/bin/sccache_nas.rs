//! Prove SHA-keyed sccache objects reached the NAS after spiceio shutdown.
//!
//! Built only with `--features loadgen`, same as `spiceio-loadgen`, so it
//! never lands in a release build. The live suite (`scripts/test-sccache.sh`)
//! owns spiceio's lifecycle; this binary is the checker that suite calls.
//!
//! `cargo test --features loadgen --bin spiceio-sccache-nas` covers the
//! checker without SMB: path safety, listing/GET against a loopback S3
//! peer, and digest match on a temp directory.

use std::fs::{self, File};
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use spiceio::crypto::{Sha256, hex_encode};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

const SHA_LEAF_LEN: usize = 64;
const SCCACHE_ZIP_MAGIC: &[u8] = b"PK\x03\x04";
const DEFAULT_VERIFY_TIMEOUT: Duration = Duration::from_secs(15);
/// Listings are XML; a 16 MiB page is already pathological.
const MAX_COLLECTED_BYTES: usize = 16 * 1024 * 1024;
/// Sanity cap on a single GET while hashing. Larger than the object-cache
/// admission default (128 MiB) so a valid sccache artifact is not rejected.
const MAX_OBJECT_BYTES: u64 = 4 * 1024 * 1024 * 1024;

#[derive(Clone, Debug, PartialEq, Eq)]
struct Object {
    key: String,
    size: u64,
    sha256: String,
}

#[derive(Clone, Debug)]
struct Manifest {
    prefix: String,
    objects: Vec<Object>,
}

fn is_hex_lower(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

fn is_sha_keyed(key: &str) -> bool {
    key.rsplit('/')
        .next()
        .is_some_and(|leaf| leaf.len() == SHA_LEAF_LEN && is_hex_lower(leaf))
}

fn cache_prefix(value: &str) -> Result<String, String> {
    let prefix = value.trim_end_matches('/');
    if prefix.is_empty()
        || prefix.contains('\\')
        || prefix
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == "..")
    {
        return Err("a nonempty cache directory prefix is required".into());
    }
    Ok(format!("{prefix}/"))
}

fn mount_path(mount: &Path, key: &str) -> Result<PathBuf, String> {
    if key.starts_with('/') || key.contains('\\') || key.split('/').any(|p| p == "." || p == "..") {
        return Err(format!("refusing to resolve key {key:?} under the mount"));
    }
    let mut path = mount.to_path_buf();
    for part in key.split('/') {
        if part.is_empty() {
            return Err(format!("refusing to resolve key {key:?} under the mount"));
        }
        path.push(part);
    }
    Ok(path)
}

#[cfg(test)]
fn sha256_hex(data: &[u8]) -> String {
    hex_encode(&spiceio::crypto::sha256(data))
}

fn sha256_file(path: &Path) -> io::Result<(String, u64)> {
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 1024 * 1024];
    let mut size = 0u64;
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        size += n as u64;
    }
    Ok((hex_encode(&hasher.finalize()), size))
}

fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            c if c.is_control() => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

fn write_manifest(path: &Path, manifest: &Manifest) -> io::Result<()> {
    let mut buf = String::from("{\n");
    buf.push_str(&format!(
        "  \"prefix\": \"{}\",\n",
        json_escape(&manifest.prefix)
    ));
    buf.push_str("  \"objects\": [\n");
    for (i, obj) in manifest.objects.iter().enumerate() {
        buf.push_str("    {\n");
        buf.push_str(&format!("      \"key\": \"{}\",\n", json_escape(&obj.key)));
        buf.push_str(&format!(
            "      \"sha256\": \"{}\",\n",
            json_escape(&obj.sha256)
        ));
        buf.push_str(&format!("      \"size\": {}\n", obj.size));
        buf.push_str("    }");
        if i + 1 < manifest.objects.len() {
            buf.push(',');
        }
        buf.push('\n');
    }
    buf.push_str("  ]\n}\n");
    fs::write(path, buf)
}

fn json_quoted_after(hay: &str, field: &str) -> Result<String, String> {
    let needle = format!("\"{field}\"");
    let rest = hay
        .split_once(&needle)
        .map(|(_, r)| r.trim_start())
        .ok_or_else(|| format!("manifest missing {field}"))?;
    let rest = rest
        .strip_prefix(':')
        .ok_or_else(|| format!("manifest missing {field}"))?
        .trim_start();
    let rest = rest
        .strip_prefix('"')
        .ok_or_else(|| format!("manifest missing {field}"))?;
    let mut out = String::new();
    let mut chars = rest.chars();
    while let Some(c) = chars.next() {
        match c {
            '"' => return Ok(out),
            '\\' => match chars.next() {
                Some('"') => out.push('"'),
                Some('\\') => out.push('\\'),
                Some('n') => out.push('\n'),
                Some(other) => out.push(other),
                None => break,
            },
            c => out.push(c),
        }
    }
    Err(format!("manifest missing {field}"))
}

fn json_u64_after(hay: &str, field: &str) -> Result<u64, String> {
    let needle = format!("\"{field}\"");
    let rest = hay
        .split_once(&needle)
        .map(|(_, r)| r.trim_start())
        .ok_or_else(|| format!("manifest missing {field}"))?;
    let rest = rest
        .strip_prefix(':')
        .ok_or_else(|| format!("manifest missing {field}"))?
        .trim_start();
    let digits: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
    digits
        .parse()
        .map_err(|_| format!("manifest missing {field}"))
}

fn load_manifest(path: &Path) -> Result<Manifest, String> {
    let text = fs::read_to_string(path).map_err(|e| format!("{path:?}: {e}"))?;
    let prefix = json_quoted_after(&text, "prefix")?;
    let mut objects = Vec::new();
    let mut idx = 0;
    while let Some(rel) = text[idx..].find("\"key\"") {
        let at = idx + rel;
        let slice = &text[at..];
        let key = json_quoted_after(slice, "key")?;
        let sha = json_quoted_after(slice, "sha256")?;
        let size = json_u64_after(slice, "size")?;
        if !is_hex_lower(&sha) || sha.len() != SHA_LEAF_LEN {
            return Err(format!("{path:?} has a malformed sha256 for {key}"));
        }
        objects.push(Object {
            key,
            size,
            sha256: sha,
        });
        idx = at + 5;
    }
    if objects.is_empty() {
        return Err(format!("{path:?} has no objects to verify"));
    }
    Ok(Manifest { prefix, objects })
}

fn xml_unescape(s: &str) -> String {
    s.replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
}

fn xml_texts<'a>(hay: &'a str, tag: &str) -> Vec<&'a str> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let mut out = Vec::new();
    let mut rest = hay;
    while let Some(start) = rest.find(&open) {
        let after = &rest[start + open.len()..];
        let Some(end) = after.find(&close) else {
            break;
        };
        out.push(&after[..end]);
        rest = &after[end + close.len()..];
    }
    out
}

fn xml_blocks<'a>(hay: &'a str, tag: &str) -> Vec<&'a str> {
    xml_texts(hay, tag)
}

struct ListPage {
    objects: Vec<(String, u64)>,
    prefixes: Vec<String>,
    truncated: bool,
    next_token: Option<String>,
}

fn parse_list_page(xml: &str) -> Result<ListPage, String> {
    if !xml.contains("ListBucketResult") {
        return Err("S3 did not return a listing".into());
    }
    let mut objects = Vec::new();
    for block in xml_blocks(xml, "Contents") {
        let key = xml_texts(block, "Key")
            .first()
            .copied()
            .ok_or_else(|| "listing object missing Key".to_string())?;
        let size = xml_texts(block, "Size")
            .first()
            .copied()
            .ok_or_else(|| "listing object missing Size".to_string())?
            .parse::<u64>()
            .map_err(|_| "listing object has a non-integer Size".to_string())?;
        objects.push((xml_unescape(key), size));
    }
    let mut prefixes = Vec::new();
    for block in xml_blocks(xml, "CommonPrefixes") {
        for prefix in xml_texts(block, "Prefix") {
            prefixes.push(xml_unescape(prefix));
        }
    }
    let truncated = xml_texts(xml, "IsTruncated")
        .first()
        .copied()
        .ok_or_else(|| "listing omitted a valid IsTruncated value".to_string())?;
    if truncated != "true" && truncated != "false" {
        return Err("listing omitted a valid IsTruncated value".into());
    }
    let next_token = xml_texts(xml, "NextContinuationToken")
        .first()
        .copied()
        .filter(|s| !s.is_empty())
        .map(xml_unescape);
    if truncated == "true" && next_token.is_none() {
        return Err("listing did not advance its continuation token".into());
    }
    Ok(ListPage {
        objects,
        prefixes,
        truncated: truncated == "true",
        next_token,
    })
}

fn encode_path(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for &b in s.as_bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' | b'/' => {
                out.push(b as char);
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

fn encode_query(s: &str) -> String {
    encode_path(s).replace('/', "%2F")
}

struct Endpoint {
    addr: String,
    host: String,
}

fn parse_endpoint(url: &str) -> Result<Endpoint, String> {
    let rest = url
        .strip_prefix("http://")
        .ok_or_else(|| "endpoint must be an HTTP origin".to_string())?;
    if rest.contains('@') || rest.contains('?') || rest.contains('#') {
        return Err("endpoint must be an HTTP origin".into());
    }
    let hostport = rest.trim_end_matches('/');
    if hostport.is_empty() || hostport.contains('/') {
        return Err("endpoint must be an HTTP origin".into());
    }
    Ok(Endpoint {
        addr: hostport.to_string(),
        host: hostport.to_string(),
    })
}

struct S3 {
    endpoint: Endpoint,
    bucket: String,
    stream: Option<TcpStream>,
}

impl S3 {
    fn new(url: &str, bucket: &str) -> Result<Self, String> {
        if bucket.is_empty() || bucket.contains('/') || bucket == "." || bucket == ".." {
            return Err("a single bucket name is required".into());
        }
        Ok(Self {
            endpoint: parse_endpoint(url)?,
            bucket: bucket.to_string(),
            stream: None,
        })
    }

    async fn ensure(&mut self) -> io::Result<&mut TcpStream> {
        if self.stream.is_none() {
            let stream = TcpStream::connect(&self.endpoint.addr).await?;
            stream.set_nodelay(true)?;
            self.stream = Some(stream);
        }
        Ok(self.stream.as_mut().expect("just set"))
    }

    fn drop_conn(&mut self) {
        self.stream = None;
    }

    async fn request(&mut self, path: &str) -> Result<(u16, Vec<u8>), String> {
        for attempt in 0..3 {
            match self.try_request(path).await {
                Ok(pair) => return Ok(pair),
                Err(e) => {
                    self.drop_conn();
                    if attempt == 2 {
                        return Err(e);
                    }
                }
            }
        }
        Err("S3 request exhausted retries".into())
    }

    async fn try_request(&mut self, path: &str) -> Result<(u16, Vec<u8>), String> {
        let host = self.endpoint.host.clone();
        let head = format!(
            "GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: keep-alive\r\nContent-Length: 0\r\n\r\n"
        );
        let stream = self.ensure().await.map_err(|e| e.to_string())?;
        stream
            .write_all(head.as_bytes())
            .await
            .map_err(|e| e.to_string())?;
        stream.flush().await.map_err(|e| e.to_string())?;

        let mut buf = Vec::new();
        loop {
            let mut chunk = [0u8; 4096];
            let n = tokio::time::timeout(Duration::from_secs(60), stream.read(&mut chunk))
                .await
                .map_err(|_| "S3 read timed out".to_string())?
                .map_err(|e| e.to_string())?;
            if n == 0 {
                break;
            }
            buf.extend_from_slice(&chunk[..n]);
            if let Some(pos) = find_headers_end(&buf) {
                let head = &buf[..pos];
                if let Some(len) = header_content_length(head) {
                    if buf.len() >= pos + len {
                        break;
                    }
                } else if header_is_chunked(head)
                    && let Some(body) = try_decode_chunked(&buf[pos..])
                {
                    let status = status_from_head(head)?;
                    return Ok((status, body));
                }
            }
            if buf.len() > MAX_COLLECTED_BYTES {
                return Err("S3 listing response exceeded 16 MiB".into());
            }
        }
        let Some(pos) = find_headers_end(&buf) else {
            return Err("S3 response missing headers".into());
        };
        let status = status_from_head(&buf[..pos])?;
        let body = if let Some(len) = header_content_length(&buf[..pos]) {
            buf.get(pos..pos + len)
                .ok_or_else(|| "S3 response body shorter than Content-Length".to_string())?
                .to_vec()
        } else if header_is_chunked(&buf[..pos]) {
            try_decode_chunked(&buf[pos..])
                .ok_or_else(|| "S3 chunked body was truncated".to_string())?
        } else {
            return Err("S3 response had neither Content-Length nor chunked encoding".into());
        };
        Ok((status, body))
    }

    /// GET an object, hashing it as bytes arrive so a large artifact does not
    /// have to fit in memory. Returns (first 4 bytes, size, sha256 hex).
    async fn get_hashed(&mut self, key: &str) -> Result<([u8; 4], u64, String), String> {
        let path = format!("/{}/{}", encode_path(&self.bucket), encode_path(key));
        for attempt in 0..3 {
            match self.try_get_hashed(&path).await {
                Ok(v) => return Ok(v),
                Err(e) => {
                    self.drop_conn();
                    if attempt == 2 {
                        return Err(e);
                    }
                }
            }
        }
        Err("S3 request exhausted retries".into())
    }

    async fn try_get_hashed(&mut self, path: &str) -> Result<([u8; 4], u64, String), String> {
        let host = self.endpoint.host.clone();
        let head = format!(
            "GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: keep-alive\r\nContent-Length: 0\r\n\r\n"
        );
        let stream = self.ensure().await.map_err(|e| e.to_string())?;
        stream
            .write_all(head.as_bytes())
            .await
            .map_err(|e| e.to_string())?;
        stream.flush().await.map_err(|e| e.to_string())?;

        let mut buf = Vec::new();
        loop {
            let mut chunk = [0u8; 4096];
            let n = tokio::time::timeout(Duration::from_secs(60), stream.read(&mut chunk))
                .await
                .map_err(|_| "S3 read timed out".to_string())?
                .map_err(|e| e.to_string())?;
            if n == 0 {
                return Err("S3 response missing headers".into());
            }
            buf.extend_from_slice(&chunk[..n]);
            if let Some(pos) = find_headers_end(&buf) {
                let status = status_from_head(&buf[..pos])?;
                if !(200..300).contains(&status) {
                    return Err(format!("GET failed with HTTP {status}"));
                }
                let leftover = buf[pos..].to_vec();
                if let Some(len) = header_content_length(&buf[..pos]) {
                    return hash_content_length(stream, leftover, len).await;
                }
                if header_is_chunked(&buf[..pos]) {
                    return hash_chunked(stream, leftover).await;
                }
                return Err("S3 response had neither Content-Length nor chunked encoding".into());
            }
            if buf.len() > MAX_COLLECTED_BYTES {
                return Err("S3 response headers exceeded 16 MiB".into());
            }
        }
    }

    async fn list_directory(
        &mut self,
        directory: &str,
        token: Option<&str>,
    ) -> Result<ListPage, String> {
        let mut query = format!(
            "list-type=2&prefix={}&delimiter=%2F&max-keys=1000",
            encode_query(directory)
        );
        if let Some(token) = token {
            query.push_str("&continuation-token=");
            query.push_str(&encode_query(token));
        }
        let path = format!("/{}?{query}", encode_path(&self.bucket));
        let (status, body) = self.request(&path).await?;
        if !(200..300).contains(&status) {
            return Err(format!(
                "LIST failed with HTTP {status}: {:?}",
                &body[..body.len().min(512)]
            ));
        }
        let xml = String::from_utf8(body).map_err(|_| "listing was not UTF-8".to_string())?;
        parse_list_page(&xml)
    }
}

fn fill_magic(magic: &mut [u8; 4], filled: &mut usize, data: &[u8]) {
    if *filled >= 4 {
        return;
    }
    let take = (4 - *filled).min(data.len());
    magic[*filled..*filled + take].copy_from_slice(&data[..take]);
    *filled += take;
}

async fn read_timed(stream: &mut TcpStream, buf: &mut [u8]) -> Result<usize, String> {
    tokio::time::timeout(Duration::from_secs(60), stream.read(buf))
        .await
        .map_err(|_| "S3 read timed out".to_string())?
        .map_err(|e| e.to_string())
}

async fn hash_content_length(
    stream: &mut TcpStream,
    leftover: Vec<u8>,
    len: usize,
) -> Result<([u8; 4], u64, String), String> {
    if len as u64 > MAX_OBJECT_BYTES {
        return Err(format!(
            "S3 object is {len} bytes; over {MAX_OBJECT_BYTES} byte sanity cap"
        ));
    }
    let mut hasher = Sha256::new();
    let mut magic = [0u8; 4];
    let mut magic_n = 0usize;
    let mut got = 0usize;
    if !leftover.is_empty() {
        let take = leftover.len().min(len);
        fill_magic(&mut magic, &mut magic_n, &leftover[..take]);
        hasher.update(&leftover[..take]);
        got += take;
    }
    let mut buf = [0u8; 64 * 1024];
    while got < len {
        let want = (len - got).min(buf.len());
        let n = read_timed(stream, &mut buf[..want]).await?;
        if n == 0 {
            return Err("S3 response body shorter than Content-Length".into());
        }
        fill_magic(&mut magic, &mut magic_n, &buf[..n]);
        hasher.update(&buf[..n]);
        got += n;
    }
    Ok((magic, got as u64, hex_encode(&hasher.finalize())))
}

async fn hash_chunked(
    stream: &mut TcpStream,
    leftover: Vec<u8>,
) -> Result<([u8; 4], u64, String), String> {
    let mut pending = leftover;
    let mut hasher = Sha256::new();
    let mut magic = [0u8; 4];
    let mut magic_n = 0usize;
    loop {
        if let Some(decoded) = try_decode_chunked(&pending) {
            if decoded.len() as u64 > MAX_OBJECT_BYTES {
                return Err(format!(
                    "S3 object is {} bytes; over {MAX_OBJECT_BYTES} byte sanity cap",
                    decoded.len()
                ));
            }
            fill_magic(&mut magic, &mut magic_n, &decoded);
            hasher.update(&decoded);
            return Ok((magic, decoded.len() as u64, hex_encode(&hasher.finalize())));
        }
        let mut buf = [0u8; 64 * 1024];
        let n = read_timed(stream, &mut buf).await?;
        if n == 0 {
            return Err("S3 chunked body was truncated".into());
        }
        pending.extend_from_slice(&buf[..n]);
        if pending.len() as u64 > MAX_OBJECT_BYTES {
            return Err(format!(
                "S3 object exceeded {MAX_OBJECT_BYTES} byte sanity cap"
            ));
        }
    }
}

fn find_headers_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n").map(|i| i + 4)
}

fn status_from_head(head: &[u8]) -> Result<u16, String> {
    let text = std::str::from_utf8(head).map_err(|_| "S3 response headers were not UTF-8")?;
    let line = text.lines().next().unwrap_or("");
    line.split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| format!("bad status line: {line}"))
}

fn header_is_chunked(head: &[u8]) -> bool {
    let Ok(text) = std::str::from_utf8(head) else {
        return false;
    };
    for line in text.lines() {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        if name.eq_ignore_ascii_case("transfer-encoding") {
            return value
                .split(',')
                .any(|p| p.trim().eq_ignore_ascii_case("chunked"));
        }
    }
    false
}

/// Decode a complete HTTP/1.1 chunked body. `None` if more bytes are needed.
fn try_decode_chunked(mut rest: &[u8]) -> Option<Vec<u8>> {
    let mut body = Vec::new();
    loop {
        let line_end = rest.windows(2).position(|w| w == b"\r\n")?;
        let size_hex = std::str::from_utf8(&rest[..line_end]).ok()?.trim();
        let size_hex = size_hex.split(';').next().unwrap_or("").trim();
        let size = usize::from_str_radix(size_hex, 16).ok()?;
        rest = &rest[line_end + 2..];
        if size == 0 {
            // Trailer, then a blank line.
            if rest.windows(2).any(|w| w == b"\r\n") {
                return Some(body);
            }
            return None;
        }
        if rest.len() < size + 2 {
            return None;
        }
        body.extend_from_slice(&rest[..size]);
        rest = &rest[size..];
        if rest.len() < 2 || &rest[..2] != b"\r\n" {
            return None;
        }
        rest = &rest[2..];
    }
}

fn header_content_length(head: &[u8]) -> Option<usize> {
    let text = std::str::from_utf8(head).ok()?;
    for line in text.lines() {
        // The status line has no colon. Using `?` on split_once would abort
        // the whole scan and leave us waiting for EOF on a keep-alive socket.
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        if name.eq_ignore_ascii_case("content-length") {
            return value.trim().parse().ok();
        }
    }
    None
}

async fn list_all(client: &mut S3, prefix: &str) -> Result<Vec<(String, u64)>, String> {
    let mut directories = vec![prefix.to_string()];
    let mut visited = std::collections::HashSet::new();
    let mut objects = Vec::new();
    while let Some(directory) = directories.pop() {
        if !visited.insert(directory.clone()) {
            continue;
        }
        let mut token = None;
        let mut seen_tokens = std::collections::HashSet::new();
        loop {
            let page = client.list_directory(&directory, token.as_deref()).await?;
            for (key, size) in page.objects {
                if !key.starts_with(&directory) {
                    return Err("listing returned a key outside the requested cache prefix".into());
                }
                objects.push((key, size));
            }
            for child in page.prefixes {
                if !child.starts_with(&directory)
                    || child.len() <= directory.len()
                    || !child.ends_with('/')
                {
                    return Err("listing returned an invalid child prefix".into());
                }
                directories.push(child);
            }
            if !page.truncated {
                break;
            }
            let next = page
                .next_token
                .ok_or_else(|| "listing did not advance its continuation token".to_string())?;
            if !seen_tokens.insert(next.clone()) {
                return Err("listing did not advance its continuation token".into());
            }
            token = Some(next);
        }
    }
    Ok(objects)
}

async fn snapshot(endpoint: &str, bucket: &str, prefix: &str, out: &Path) -> Result<(), String> {
    let prefix = cache_prefix(prefix)?;
    let mut client = S3::new(endpoint, bucket)?;
    let listed = list_all(&mut client, &prefix).await?;
    let mut objects = Vec::new();
    for (key, listed_size) in listed {
        // sccache also drops a `.sccache_check` probe under the prefix;
        // only the SHA-256-keyed compiler results are the durability contract.
        if !is_sha_keyed(&key) {
            continue;
        }
        let (magic, size, digest) = client.get_hashed(&key).await?;
        if magic.as_slice() != SCCACHE_ZIP_MAGIC {
            return Err(format!(
                "{key} is not an sccache zip (magic={magic:?}); refusing to treat it as a compiler-cache object"
            ));
        }
        if size != listed_size {
            return Err(format!(
                "{key}: listing size {listed_size} != GET body {size}"
            ));
        }
        objects.push(Object {
            sha256: digest,
            size,
            key,
        });
    }
    if objects.is_empty() {
        return Err(format!("no SHA-256-keyed sccache objects under {prefix:?}"));
    }
    let total: u64 = objects.iter().map(|o| o.size).sum();
    let count = objects.len();
    write_manifest(
        out,
        &Manifest {
            prefix: prefix.clone(),
            objects,
        },
    )
    .map_err(|e| e.to_string())?;
    println!(
        "[metrics] nas_snapshot objects={count} sha_keyed={count} bytes={total} prefix={prefix}"
    );
    Ok(())
}

fn refresh_ancestors(path: &Path, mount: &Path) {
    let Some(mut current) = path.parent().map(Path::to_path_buf) else {
        return;
    };
    if !current.starts_with(mount) {
        return;
    }
    loop {
        let _ = fs::read_dir(&current);
        if current == mount {
            break;
        }
        match current.parent() {
            Some(parent) => current = parent.to_path_buf(),
            None => break,
        }
    }
}

fn verify_mount(manifest: &Manifest, mount: &Path, timeout: Duration) -> Result<(), String> {
    if !mount.is_dir() {
        return Err(format!("mount {mount:?} is not a directory"));
    }
    let paths: Vec<(&Object, PathBuf)> = manifest
        .objects
        .iter()
        .map(|obj| mount_path(mount, &obj.key).map(|p| (obj, p)))
        .collect::<Result<Vec<_>, _>>()?;
    let deadline = Instant::now() + timeout;
    loop {
        let missing: Vec<_> = paths.iter().filter(|(_, p)| !p.is_file()).collect();
        if missing.is_empty() {
            break;
        }
        for (_, path) in &missing {
            refresh_ancestors(path, mount);
        }
        if Instant::now() >= deadline {
            let sample: Vec<_> = missing
                .iter()
                .take(8)
                .map(|(obj, _)| obj.key.as_str())
                .collect();
            return Err(format!(
                "{} of {} sccache object(s) missing on {} after {}s (smbfs directory cache can lag a wire-protocol write): {}",
                missing.len(),
                paths.len(),
                mount.display(),
                timeout.as_secs(),
                sample.join(", ")
            ));
        }
        std::thread::sleep(Duration::from_millis(500));
    }

    let mut errors = Vec::new();
    for (obj, path) in &paths {
        let (digest, size) = sha256_file(path).map_err(|e| format!("{}: {e}", obj.key))?;
        if size != obj.size {
            errors.push(format!(
                "{}: size {size} != acknowledged {}",
                obj.key, obj.size
            ));
        } else if digest != obj.sha256 {
            errors.push(format!(
                "{}: sha256 {digest} != acknowledged {}",
                obj.key, obj.sha256
            ));
        }
    }
    if !errors.is_empty() {
        return Err(format!(
            "{} of {} sccache object(s) did not match on {}: {}",
            errors.len(),
            paths.len(),
            mount.display(),
            errors
                .iter()
                .take(8)
                .cloned()
                .collect::<Vec<_>>()
                .join("; ")
        ));
    }
    Ok(())
}

async fn verify_http(manifest: &Manifest, endpoint: &str, bucket: &str) -> Result<(), String> {
    let mut client = S3::new(endpoint, bucket)?;
    let mut errors = Vec::new();
    for obj in &manifest.objects {
        match client.get_hashed(&obj.key).await {
            Ok((_magic, size, digest)) => {
                if size != obj.size {
                    errors.push(format!(
                        "{}: size {size} != acknowledged {}",
                        obj.key, obj.size
                    ));
                } else if digest != obj.sha256 {
                    errors.push(format!(
                        "{}: sha256 {digest} != acknowledged {}",
                        obj.key, obj.sha256
                    ));
                }
            }
            Err(e) => errors.push(format!("{}: {e}", obj.key)),
        }
    }
    if !errors.is_empty() {
        return Err(format!(
            "{} of {} sccache object(s) did not match through {endpoint}: {}",
            errors.len(),
            manifest.objects.len(),
            errors
                .iter()
                .take(8)
                .cloned()
                .collect::<Vec<_>>()
                .join("; ")
        ));
    }
    Ok(())
}

fn print_verify_ok(manifest: &Manifest, via: &str) {
    let sha_keyed = manifest
        .objects
        .iter()
        .filter(|o| is_sha_keyed(&o.key))
        .count();
    let total: u64 = manifest.objects.iter().map(|o| o.size).sum();
    println!(
        "[metrics] nas_verify objects={} sha_keyed={sha_keyed} bytes={total} via={via}",
        manifest.objects.len()
    );
    println!(
        "PASS: {} sccache object(s) ({sha_keyed} SHA-256-keyed) matched on the NAS after shutdown",
        manifest.objects.len()
    );
}

fn flag(args: &[String], i: &mut usize) -> Result<String, String> {
    *i += 1;
    args.get(*i)
        .cloned()
        .ok_or_else(|| "missing flag value".to_string())
}

fn usage() -> ! {
    eprintln!(
        "spiceio-sccache-nas — SHA-256 check that sccache objects reached the NAS

  snapshot --endpoint URL --bucket NAME --prefix PREFIX --out PATH
  verify   --manifest PATH (--mount PATH | --endpoint URL --bucket NAME) [--timeout SECS]
"
    );
    std::process::exit(2);
}

#[tokio::main]
async fn main() {
    if let Err(e) = run().await {
        eprintln!("FAIL: sccache NAS check: {e}");
        std::process::exit(1);
    }
}

async fn run() -> Result<(), String> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let command = args.first().map(String::as_str).unwrap_or("");
    match command {
        "snapshot" => {
            let mut endpoint = None;
            let mut bucket = None;
            let mut prefix = None;
            let mut out = None;
            let mut i = 1;
            while i < args.len() {
                match args[i].as_str() {
                    "--endpoint" => endpoint = Some(flag(&args, &mut i)?),
                    "--bucket" => bucket = Some(flag(&args, &mut i)?),
                    "--prefix" => prefix = Some(flag(&args, &mut i)?),
                    "--out" => out = Some(flag(&args, &mut i)?),
                    other => return Err(format!("unknown flag {other}")),
                }
                i += 1;
            }
            snapshot(
                &endpoint.ok_or("missing --endpoint")?,
                &bucket.ok_or("missing --bucket")?,
                &prefix.ok_or("missing --prefix")?,
                Path::new(&out.ok_or("missing --out")?),
            )
            .await
        }
        "verify" => {
            let mut manifest = None;
            let mut mount = None;
            let mut endpoint = None;
            let mut bucket = None;
            let mut timeout = DEFAULT_VERIFY_TIMEOUT;
            let mut i = 1;
            while i < args.len() {
                match args[i].as_str() {
                    "--manifest" => manifest = Some(flag(&args, &mut i)?),
                    "--mount" => mount = Some(flag(&args, &mut i)?),
                    "--endpoint" => endpoint = Some(flag(&args, &mut i)?),
                    "--bucket" => bucket = Some(flag(&args, &mut i)?),
                    "--timeout" => {
                        let secs: f64 = flag(&args, &mut i)?
                            .parse()
                            .map_err(|_| "invalid --timeout".to_string())?;
                        timeout = Duration::from_secs_f64(secs);
                    }
                    other => return Err(format!("unknown flag {other}")),
                }
                i += 1;
            }
            let manifest = load_manifest(Path::new(&manifest.ok_or("missing --manifest")?))?;
            if let Some(mount) = mount {
                verify_mount(&manifest, Path::new(&mount), timeout)?;
                print_verify_ok(&manifest, &format!("mount={mount}"));
                Ok(())
            } else if let (Some(endpoint), Some(bucket)) = (endpoint, bucket) {
                verify_http(&manifest, &endpoint, &bucket).await?;
                print_verify_ok(&manifest, &format!("http={endpoint}"));
                Ok(())
            } else {
                Err("verify requires --mount or --endpoint and --bucket".into())
            }
        }
        _ => usage(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;
    use std::sync::Arc;
    use tokio::net::TcpListener;
    use tokio::sync::Mutex;

    const LEAF: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    #[test]
    fn sha_keyed_leaf_and_probes() {
        assert!(is_sha_keyed(&format!("a/b/c/{LEAF}")));
        assert!(!is_sha_keyed("a/b/c/not-a-hash"));
        assert!(!is_sha_keyed("prefix/.sccache_check"));
        assert!(!is_sha_keyed(&format!(
            "a/b/c/{}",
            LEAF.to_ascii_uppercase()
        )));
    }

    #[test]
    fn mount_path_rejects_traversal() {
        let mount = Path::new("/Volumes/share");
        assert_eq!(
            mount_path(mount, &format!("pre/a/b/c/{LEAF}")).unwrap(),
            mount.join("pre").join("a").join("b").join("c").join(LEAF)
        );
        for bad in ["/etc/passwd", "../escape", "a/../b", "a\\b", "a//b"] {
            assert!(mount_path(mount, bad).is_err(), "accepted {bad}");
        }
    }

    #[test]
    fn cache_prefix_rejects_dot_segments() {
        assert_eq!(
            cache_prefix("spiceio-test/sccache").unwrap(),
            "spiceio-test/sccache/"
        );
        assert!(cache_prefix("../sccache").is_err());
        assert!(cache_prefix("").is_err());
    }

    #[test]
    fn content_length_skips_status_line() {
        let head =
            b"HTTP/1.1 200 OK\r\nContent-Type: application/xml\r\nContent-Length: 1862\r\n\r\n";
        assert_eq!(header_content_length(head), Some(1862));
    }

    #[test]
    fn chunked_body_round_trip() {
        let raw = b"5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n";
        assert_eq!(try_decode_chunked(raw).unwrap(), b"hello world");
        assert!(try_decode_chunked(b"5\r\nhel").is_none());
    }

    #[test]
    fn sha256_empty_vector() {
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn list_page_requires_is_truncated() {
        let xml = format!(
            "<ListBucketResult>\
               <Contents><Key>pre/a/b/c/{LEAF}</Key><Size>4</Size></Contents>\
             </ListBucketResult>"
        );
        let err = match parse_list_page(&xml) {
            Ok(_) => panic!("expected missing IsTruncated to fail"),
            Err(e) => e,
        };
        assert!(err.contains("IsTruncated"), "{err}");
    }

    #[test]
    fn list_page_reads_contents_and_common_prefixes() {
        let xml = format!(
            "<ListBucketResult>\
               <IsTruncated>false</IsTruncated>\
               <Contents><Key>pre/a/b/c/{LEAF}</Key><Size>4</Size></Contents>\
               <Contents><Key>pre/.sccache_check</Key><Size>4</Size></Contents>\
               <CommonPrefixes><Prefix>pre/d/</Prefix></CommonPrefixes>\
             </ListBucketResult>"
        );
        let page = parse_list_page(&xml).unwrap();
        assert_eq!(page.objects.len(), 2);
        assert_eq!(page.objects[0].0, format!("pre/a/b/c/{LEAF}"));
        assert_eq!(page.prefixes, vec!["pre/d/".to_string()]);
        assert!(!page.truncated);
    }

    #[test]
    fn manifest_round_trip() {
        let dir = std::env::temp_dir().join(format!("spiceio-nas-manifest-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("m.json");
        let original = Manifest {
            prefix: "pre/".into(),
            objects: vec![Object {
                key: format!("pre/a/b/c/{LEAF}"),
                size: 4,
                sha256: LEAF.to_string(),
            }],
        };
        write_manifest(&path, &original).unwrap();
        let loaded = load_manifest(&path).unwrap();
        assert_eq!(loaded.prefix, "pre/");
        assert_eq!(loaded.objects, original.objects);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn verify_mount_matches_temp_files() {
        let root = std::env::temp_dir().join(format!("spiceio-nas-mount-{}", std::process::id()));
        let key = format!("pre/a/b/c/{LEAF}");
        let path = mount_path(&root, &key).unwrap();
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        let body = {
            let mut b = SCCACHE_ZIP_MAGIC.to_vec();
            b.extend_from_slice(b"body");
            b
        };
        fs::write(&path, &body).unwrap();
        let manifest = Manifest {
            prefix: "pre/".into(),
            objects: vec![Object {
                key,
                size: body.len() as u64,
                sha256: sha256_hex(&body),
            }],
        };
        verify_mount(&manifest, &root, Duration::from_secs(1)).unwrap();
        fs::remove_dir_all(&root).unwrap();
    }

    struct Peer {
        objects: Vec<(String, Vec<u8>)>,
        prefixes: Vec<(String, Vec<String>)>,
    }

    async fn serve_s3(peer: Arc<Mutex<Peer>>) -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    break;
                };
                let peer = Arc::clone(&peer);
                tokio::spawn(async move {
                    // Keep-alive: the live checker reuses one TCP connection.
                    // Closing after the first reply would hide the Content-Length
                    // status-line bug (EOF looks like a complete body).
                    loop {
                        let mut buf = vec![0u8; 8192];
                        let n = match stream.read(&mut buf).await {
                            Ok(0) | Err(_) => return,
                            Ok(n) => n,
                        };
                        let req = String::from_utf8_lossy(&buf[..n]);
                        let line = req.lines().next().unwrap_or("");
                        let path = line.split_whitespace().nth(1).unwrap_or("/");
                        let body = {
                            let guard = peer.lock().await;
                            s3_reply(path, &guard)
                        };
                        if stream.write_all(&body).await.is_err() {
                            return;
                        }
                    }
                });
            }
        });
        addr
    }

    fn s3_reply(path: &str, peer: &Peer) -> Vec<u8> {
        let path = path.trim_start_matches("/bucket");
        if let Some(rest) = path.strip_prefix('?') {
            let prefix = query_value(rest, "prefix").unwrap_or_default();
            let mut xml = String::from(
                "<ListBucketResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">\
                 <IsTruncated>false</IsTruncated>",
            );
            for (key, body) in &peer.objects {
                if key.starts_with(&prefix) && !key[prefix.len()..].contains('/') {
                    xml.push_str(&format!(
                        "<Contents><Key>{key}</Key><Size>{}</Size></Contents>",
                        body.len()
                    ));
                }
            }
            for (dir, children) in &peer.prefixes {
                if dir == &prefix {
                    for child in children {
                        xml.push_str(&format!(
                            "<CommonPrefixes><Prefix>{child}</Prefix></CommonPrefixes>"
                        ));
                    }
                }
            }
            xml.push_str("</ListBucketResult>");
            http_ok(xml.into_bytes(), "application/xml")
        } else {
            let key = path.trim_start_matches('/');
            if let Some((_, body)) = peer.objects.iter().find(|(k, _)| k == key) {
                http_ok(body.clone(), "application/octet-stream")
            } else {
                let body = b"NoSuchKey";
                let head = format!(
                    "HTTP/1.1 404 Not Found\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                let mut out = head.into_bytes();
                out.extend_from_slice(body);
                out
            }
        }
    }

    fn query_value(query: &str, name: &str) -> Option<String> {
        for part in query.split('&') {
            let (k, v) = part.split_once('=')?;
            if k == name {
                return Some(v.replace("%2F", "/"));
            }
        }
        None
    }

    fn http_ok(body: Vec<u8>, ctype: &str) -> Vec<u8> {
        let head = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\nConnection: keep-alive\r\n\r\n",
            body.len()
        );
        let mut out = head.into_bytes();
        out.extend_from_slice(&body);
        out
    }

    #[tokio::test]
    async fn snapshot_skips_probe_and_hashes_zip() {
        let key = format!("pre/a/b/c/{LEAF}");
        let mut zip = SCCACHE_ZIP_MAGIC.to_vec();
        zip.extend_from_slice(b"obj");
        let peer = Arc::new(Mutex::new(Peer {
            objects: vec![
                (key.clone(), zip.clone()),
                ("pre/.sccache_check".into(), b"Hell".to_vec()),
            ],
            prefixes: vec![
                ("pre/".into(), vec!["pre/a/".into()]),
                ("pre/a/".into(), vec!["pre/a/b/".into()]),
                ("pre/a/b/".into(), vec!["pre/a/b/c/".into()]),
                ("pre/a/b/c/".into(), vec![]),
            ],
        }));
        let addr = serve_s3(peer).await;
        let dir = std::env::temp_dir().join(format!("spiceio-nas-snap-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let out = dir.join("m.json");
        snapshot(&format!("http://{addr}"), "bucket", "pre", &out)
            .await
            .unwrap();
        let loaded = load_manifest(&out).unwrap();
        assert_eq!(loaded.objects.len(), 1);
        assert_eq!(loaded.objects[0].key, key);
        assert_eq!(loaded.objects[0].sha256, sha256_hex(&zip));
        verify_http(&loaded, &format!("http://{addr}"), "bucket")
            .await
            .unwrap();
        fs::remove_dir_all(&dir).unwrap();
    }
}
