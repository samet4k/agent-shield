use base64::Engine;
use regex::Regex;
use std::sync::LazyLock;

static HEX_ESCAPE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\$'\\x[0-9a-fA-F]{2}(?:\\x[0-9a-fA-F]{2})*'").unwrap());
static BASE64_PIPE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"base64\s+(-d|--decode)").unwrap());
static CONCAT_QUOTES: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"r?""([^"]*)""\s*r?""([^"]*)""#).unwrap());
static PS_ENCODED: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)(?:-|/)(?:e|ec|enc|encodedcommand)\s+").unwrap()
});
static PS_IEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)\b(?:invoke-expression|iex)\b").unwrap());
static PS_TICK: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"`[a-zA-Z]").unwrap());
static PS_B64_CONVERT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\[system\.convert\]::frombase64string").unwrap()
});

/// Result of normalizing a potentially obfuscated command.
#[derive(Debug, Clone, Default)]
pub struct NormalizationResult {
    pub normalized: String,
    pub obfuscation_detected: bool,
    pub techniques: Vec<String>,
    pub decoded_fragments: Vec<String>,
}

/// Normalize obfuscated shell commands for consistent policy matching.
pub fn normalize(command: &str) -> NormalizationResult {
    let mut result = NormalizationResult {
        normalized: command.to_string(),
        ..Default::default()
    };

    if BASE64_PIPE.is_match(command) {
        result.obfuscation_detected = true;
        result.techniques.push("base64-pipe".into());
        if let Some(decoded) = try_decode_base64_payload(command) {
            result.decoded_fragments.push(decoded.clone());
            result.normalized.push(' ');
            result.normalized.push_str(&decoded);
        }
    }

    for cap in HEX_ESCAPE.captures_iter(command) {
        result.obfuscation_detected = true;
        result.techniques.push("hex-escape".into());
        if let Some(decoded) = decode_hex_escape(cap.get(0).map(|m| m.as_str()).unwrap_or("")) {
            result.decoded_fragments.push(decoded.clone());
            result.normalized = result
                .normalized
                .replace(cap.get(0).map(|m| m.as_str()).unwrap_or(""), &decoded);
        }
    }

    for cap in CONCAT_QUOTES.captures_iter(command) {
        result.obfuscation_detected = true;
        result.techniques.push("string-concat".into());
        let combined = format!(
            "{}{}",
            cap.get(1).map(|m| m.as_str()).unwrap_or(""),
            cap.get(2).map(|m| m.as_str()).unwrap_or("")
        );
        result.decoded_fragments.push(combined);
    }

    detect_powershell_obfuscation(command, &mut result);

    result.normalized = collapse_whitespace(&result.normalized);
    result
}

fn detect_powershell_obfuscation(command: &str, result: &mut NormalizationResult) {
    if PS_ENCODED.is_match(command) {
        result.obfuscation_detected = true;
        result.techniques.push("powershell-encoded-command".into());
        if let Some(decoded) = try_decode_powershell_encoded(command) {
            result.decoded_fragments.push(decoded.clone());
            result.normalized.push(' ');
            result.normalized.push_str(&decoded);
        }
    }
    if PS_IEX.is_match(command) {
        result.obfuscation_detected = true;
        result.techniques.push("powershell-iex".into());
    }
    if PS_TICK.is_match(command) {
        result.obfuscation_detected = true;
        result.techniques.push("powershell-tick-escape".into());
        result.normalized = PS_TICK
            .replace_all(&result.normalized, |caps: &regex::Captures| {
                caps[0].chars().nth(1).map(|c| c.to_string()).unwrap_or_default()
            })
            .into_owned();
    }
    if PS_B64_CONVERT.is_match(command) {
        result.obfuscation_detected = true;
        result.techniques.push("powershell-b64-convert".into());
    }
}

fn try_decode_powershell_encoded(command: &str) -> Option<String> {
    let re = Regex::new(r"(?i)(?:-|/)(?:e|ec|enc|encodedcommand)\s+([A-Za-z0-9+/=]+)").ok()?;
    let cap = re.captures(command)?;
    let b64 = cap.get(1)?.as_str();
    let bytes = base64::engine::general_purpose::STANDARD.decode(b64).ok()?;
    let utf16: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|chunk| u16::from_le_bytes([chunk[0], chunk.get(1).copied().unwrap_or(0)]))
        .collect();
    String::from_utf16(&utf16).ok()
}

fn try_decode_base64_payload(command: &str) -> Option<String> {
    let re = Regex::new(r#"echo\s+['"]([A-Za-z0-9+/=]+)['"]"#).ok()?;
    let cap = re.captures(command)?;
    let b64 = cap.get(1)?.as_str();
    let bytes = base64::engine::general_purpose::STANDARD.decode(b64).ok()?;
    String::from_utf8(bytes).ok()
}

fn decode_hex_escape(s: &str) -> Option<String> {
    let inner = s.strip_prefix("$'")?.strip_suffix('\'')?;
    let parts: Vec<&str> = inner.split("\\x").filter(|p| !p.is_empty()).collect();
    let mut bytes = Vec::new();
    for part in parts {
        if part.len() >= 2 {
            if let Ok(b) = u8::from_str_radix(&part[..2], 16) {
                bytes.push(b);
            }
        }
    }
    String::from_utf8(bytes).ok()
}

fn collapse_whitespace(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_hex_escape() {
        let r = normalize(r"echo $'\x72\x6d'");
        assert!(r.obfuscation_detected);
        assert!(r.normalized.contains("rm"));
    }

    #[test]
    fn detects_base64_pipe() {
        let cmd = r#"echo "cm0gLXJmIC8=" | base64 -d | bash"#;
        let r = normalize(cmd);
        assert!(r.obfuscation_detected);
        assert!(r.techniques.contains(&"base64-pipe".to_string()));
    }

    #[test]
    fn detects_powershell_iex() {
        let r = normalize("Invoke-Expression (Get-Content evil.ps1)");
        assert!(r.obfuscation_detected);
        assert!(r.techniques.contains(&"powershell-iex".to_string()));
    }

    #[test]
    fn detects_powershell_tick_escape() {
        let r = normalize("`r`m -rf /tmp/test");
        assert!(r.obfuscation_detected);
        assert!(r.normalized.contains("rm"));
    }
}