#[Helper]
struct SesameTransportHelper;
impl BehaviorHttpAdapter for SesameTransportHelper {
    fn exchange(&self, request: &BehaviorHttpRequest, execution: &BehaviorExecution) -> BehaviorResult<BehaviorValue> {
        let authority = Self::origin()?;
        let deadline = Self::deadline(execution.deadline)?;
        let proxy = Self::proxy();
        let target = Self::target(&authority, request, proxy.is_some());
        let message = Self::message(&authority, &target, request)?;
        let mut stream = Self::connect(proxy.as_deref().unwrap_or(&authority), deadline)?;
        std::io::Write::write_all(&mut stream, &message).map_err(|_| Self::failure())?;
        let raw = Self::read(&mut stream, request.max_response_bytes, deadline)?;
        Self::answer(&raw, request.max_response_bytes)
    }
}

impl SesameTransportHelper {
    const SNAPSHOT_VARIABLE: &str = "YON_APPLICATION_JSON";
    const PLAIN_PREFIX: &str = "http://";
    const LOOPBACK_HOSTS: [&str; 3] = ["localhost", "127.0.0.1", "[::1]"];
    const PROXY_VARIABLES: [&str; 2] = ["HTTP_PROXY", "http_proxy"];
    const DEFAULT_PORT: &str = "80";
    const PORT_SEPARATOR: char = ':';
    const ROOT_PATH: char = '/';
    const IPV6_END: char = ']';
    const LINE_END: &[u8] = b"\r\n";
    const HEAD_END: &[u8] = b"\r\n\r\n";
    const HEAD_LIMIT: usize = 65_536;
    const READ_CHUNK: usize = 16_384;
    const HEXADECIMAL: u32 = 16;
    const REDIRECT_STATUSES: std::ops::Range<u16> = 300..400;
    const CHUNKED_HEADER: &str = "transfer-encoding: chunked";
    const UNRESERVED: &str = "-._~";
    const ADAPTER_CODE: &str = "adapter";
    const ORIGIN_RULE: &str = "sesame.origin must be http on localhost, 127.0.0.1 or [::1]: this Rust transport has no TLS";
    const TRANSPORT_RULE: &str = "SESAME could not be reached, or did not answer before the deadline";
    const ANSWER_RULE: &str = "SESAME's answer is not a readable HTTP/1.1 answer";
    const REDIRECT_RULE: &str = "SESAME answered with a redirect, which this transport never follows";
    const SIZE_RULE: &str = "SESAME's answer is larger than the response limit";

    fn new() -> Self {
        Self
    }

    fn origin() -> BehaviorResult<String> {
        let snapshot = std::env::var(Self::SNAPSHOT_VARIABLE).map_err(|_| Self::refused(Self::ORIGIN_RULE))?;
        let parsed = BehaviorValue::from(Json::parse(&snapshot).map_err(|_| Self::refused(Self::ORIGIN_RULE))?);
        let configured = parsed.get("yon").and_then(|yon| yon.get("sesame")).and_then(|sesame| sesame.get("origin"));
        let Some(BehaviorValue::String(origin)) = configured else {
            return Err(Self::refused(Self::ORIGIN_RULE));
        };
        let address = origin.strip_prefix(Self::PLAIN_PREFIX).ok_or_else(|| Self::refused(Self::ORIGIN_RULE))?;
        let authority = address.strip_suffix(Self::ROOT_PATH).unwrap_or(address);
        if !Self::loopback(authority) {
            return Err(Self::refused(Self::ORIGIN_RULE));
        }
        Ok(authority.to_owned())
    }

    fn loopback(authority: &str) -> bool {
        let (host, port) = Self::host_and_port(authority);
        Self::LOOPBACK_HOSTS.contains(&host) && port.is_none_or(|digits| digits.parse::<u16>().is_ok())
    }

    fn host_and_port(authority: &str) -> (&str, Option<&str>) {
        match authority.rfind(Self::PORT_SEPARATOR) {
            Some(at) if !authority[at..].contains(Self::IPV6_END) => (&authority[..at], Some(&authority[at + 1..])),
            _ => (authority, None),
        }
    }

    fn proxy() -> Option<String> {
        let configured = Self::PROXY_VARIABLES.iter().find_map(|name| std::env::var(name).ok().filter(|value| !value.is_empty()))?;
        let address = configured.strip_prefix(Self::PLAIN_PREFIX).unwrap_or(&configured);
        Some(address.strip_suffix(Self::ROOT_PATH).unwrap_or(address).to_owned())
    }

    fn deadline(epoch_milliseconds: u64) -> BehaviorResult<std::time::Instant> {
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_err(|_| Self::failure())?;
        let left = std::time::Duration::from_millis(epoch_milliseconds).checked_sub(now).ok_or_else(Self::failure)?;
        Ok(std::time::Instant::now() + left)
    }

    fn remaining(deadline: std::time::Instant) -> BehaviorResult<std::time::Duration> {
        deadline.checked_duration_since(std::time::Instant::now()).filter(|left| !left.is_zero()).ok_or_else(Self::failure)
    }

    fn target(authority: &str, request: &BehaviorHttpRequest, through_proxy: bool) -> String {
        let local = format!("{}{}", request.path, Self::query(&request.query));
        if through_proxy {
            return format!("{}{authority}{local}", Self::PLAIN_PREFIX);
        }
        local
    }

    fn query(values: &BehaviorValue) -> String {
        let BehaviorValue::Object(entries) = values else {
            return String::new();
        };
        let pairs: Vec<String> = entries
            .iter()
            .map(|(name, value)| format!("{}={}", Self::encoded(name), Self::encoded(&Self::text(value))))
            .collect();
        if pairs.is_empty() {
            return String::new();
        }
        format!("?{}", pairs.join("&"))
    }

    fn text(value: &BehaviorValue) -> String {
        match value {
            BehaviorValue::String(text) => text.clone(),
            BehaviorValue::Number(number) => number.to_string(),
            BehaviorValue::Bool(flag) => flag.to_string(),
            _ => String::new(),
        }
    }

    fn encoded(text: &str) -> String {
        text.bytes()
            .map(|byte| {
                if byte.is_ascii_alphanumeric() || Self::UNRESERVED.as_bytes().contains(&byte) {
                    char::from(byte).to_string()
                } else {
                    format!("%{byte:02X}")
                }
            })
            .collect()
    }

    fn message(authority: &str, target: &str, request: &BehaviorHttpRequest) -> BehaviorResult<Vec<u8>> {
        let mut head = format!(
            "{} {target} HTTP/1.1\r\nHost: {authority}\r\nConnection: close\r\nContent-Type: application/json\r\nAccept: application/json\r\n",
            request.method
        );
        if let BehaviorValue::Object(headers) = &request.headers {
            for (name, value) in headers {
                head.push_str(&format!("{name}: {}\r\n", Self::text(value)));
            }
        }
        let body = match &request.body {
            Some(value) => value.to_json(request.max_response_bytes)?,
            None => String::new(),
        };
        if request.body.is_some() {
            head.push_str(&format!("Content-Length: {}\r\n", body.len()));
        }
        head.push_str("\r\n");
        head.push_str(&body);
        Ok(head.into_bytes())
    }

    fn connect(authority: &str, deadline: std::time::Instant) -> BehaviorResult<std::net::TcpStream> {
        let address = match Self::host_and_port(authority).1 {
            Some(_) => authority.to_owned(),
            None => format!("{authority}{}{}", Self::PORT_SEPARATOR, Self::DEFAULT_PORT),
        };
        let socket = std::net::ToSocketAddrs::to_socket_addrs(&address)
            .map_err(|_| Self::failure())?
            .next()
            .ok_or_else(Self::failure)?;
        let stream = std::net::TcpStream::connect_timeout(&socket, Self::remaining(deadline)?).map_err(|_| Self::failure())?;
        stream.set_read_timeout(Some(Self::remaining(deadline)?)).map_err(|_| Self::failure())?;
        stream.set_write_timeout(Some(Self::remaining(deadline)?)).map_err(|_| Self::failure())?;
        Ok(stream)
    }

    fn read(stream: &mut std::net::TcpStream, limit: usize, deadline: std::time::Instant) -> BehaviorResult<Vec<u8>> {
        let mut raw = Vec::new();
        let mut chunk = vec![0_u8; Self::READ_CHUNK];
        loop {
            Self::remaining(deadline)?;
            let count = std::io::Read::read(stream, &mut chunk).map_err(|_| Self::failure())?;
            if count == 0 {
                return Ok(raw);
            }
            raw.extend_from_slice(&chunk[..count]);
            if raw.len() > limit + Self::HEAD_LIMIT {
                return Err(Self::refused(Self::SIZE_RULE));
            }
        }
    }

    fn answer(raw: &[u8], limit: usize) -> BehaviorResult<BehaviorValue> {
        let split = Self::find(raw, Self::HEAD_END).ok_or_else(|| Self::refused(Self::ANSWER_RULE))?;
        let head = std::str::from_utf8(&raw[..split]).map_err(|_| Self::refused(Self::ANSWER_RULE))?;
        let status = Self::status(head)?;
        if Self::REDIRECT_STATUSES.contains(&status) {
            return Err(Self::refused(Self::REDIRECT_RULE));
        }
        let body = Self::body(head, &raw[split + Self::HEAD_END.len()..])?;
        if body.len() > limit {
            return Err(Self::refused(Self::SIZE_RULE));
        }
        Ok(BehaviorValue::object([
            ("status", BehaviorValue::Number(f64::from(status))),
            ("body", Self::json_or_nothing(&body)),
        ]))
    }

    fn find(raw: &[u8], wanted: &[u8]) -> Option<usize> {
        raw.windows(wanted.len()).position(|window| window == wanted)
    }

    fn status(head: &str) -> BehaviorResult<u16> {
        head.split(' ').nth(1).and_then(|code| code.parse().ok()).ok_or_else(|| Self::refused(Self::ANSWER_RULE))
    }

    fn body(head: &str, rest: &[u8]) -> BehaviorResult<Vec<u8>> {
        if head.to_ascii_lowercase().contains(Self::CHUNKED_HEADER) {
            return Self::joined_chunks(rest);
        }
        Ok(rest.to_vec())
    }

    fn joined_chunks(mut rest: &[u8]) -> BehaviorResult<Vec<u8>> {
        let mut body = Vec::new();
        loop {
            let line = Self::find(rest, Self::LINE_END).ok_or_else(|| Self::refused(Self::ANSWER_RULE))?;
            let size = Self::chunk_size(&rest[..line])?;
            rest = &rest[line + Self::LINE_END.len()..];
            if size == 0 {
                return Ok(body);
            }
            let next = size + Self::LINE_END.len();
            if rest.len() < next {
                return Err(Self::refused(Self::ANSWER_RULE));
            }
            body.extend_from_slice(&rest[..size]);
            rest = &rest[next..];
        }
    }

    fn chunk_size(line: &[u8]) -> BehaviorResult<usize> {
        let text = std::str::from_utf8(line).map_err(|_| Self::refused(Self::ANSWER_RULE))?;
        let digits = text.split(';').next().unwrap_or_default().trim();
        usize::from_str_radix(digits, Self::HEXADECIMAL).map_err(|_| Self::refused(Self::ANSWER_RULE))
    }

    fn json_or_nothing(body: &[u8]) -> BehaviorValue {
        std::str::from_utf8(body)
            .ok()
            .and_then(|text| Json::parse(text).ok())
            .map(BehaviorValue::from)
            .unwrap_or(BehaviorValue::Null)
    }

    fn failure() -> BehaviorError {
        Self::refused(Self::TRANSPORT_RULE)
    }

    fn refused(rule: &'static str) -> BehaviorError {
        BehaviorError { code: Self::ADAPTER_CODE, message: rule, path: None }
    }
}
