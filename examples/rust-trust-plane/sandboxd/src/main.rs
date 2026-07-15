use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::env;
use std::fs;
use std::io::{Read, Write};
use std::net::Ipv4Addr;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::process::{Command, Stdio};

const VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
struct SandboxConfig {
    runtime: String,
    memory_limit_mb: u32,
    cpu_limit: f64,
    pids_limit: u32,
    tmp_size_mb: u32,
    network_policy: String,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
struct NetworkProfile {
    name: String,
    #[serde(rename = "type")]
    profile_type: String,
    #[serde(default)]
    egress_allowlist: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
struct PlanRequest {
    instance_key: String,
    image_tag: String,
    runtime: String,
    control_mode: String,
    effective_network_policy: String,
    #[serde(default)]
    memory_reservation_mb: u32,
    network_profile: NetworkProfile,
    config: SandboxConfig,
    #[serde(default)]
    runtime_env: Map<String, Value>,
    #[serde(default)]
    secret_env_keys: Vec<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct PlanResponse {
    version: &'static str,
    container_name: String,
    args: Vec<String>,
    runtime: String,
    control_mode: String,
    effective_network_policy: String,
    network_name: String,
    secret_values_in_argv: bool,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct EgressApplyRequest {
    network_name: String,
    bridge_interface: String,
    chain_name: String,
    #[serde(default)]
    allowed_ips: Vec<String>,
    #[serde(default)]
    open: bool,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct EgressCleanupRequest {
    network_name: String,
    bridge_interface: Option<String>,
    chain_name: String,
}

const BLOCKED_RANGES: &[&str] = &[
    "169.254.169.254/32",
    "169.254.0.0/16",
    "127.0.0.0/8",
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "100.64.0.0/10",
];

fn sanitize_container_name(instance_key: &str) -> String {
    let mut out = String::new();
    let mut last_dash = false;
    for ch in instance_key.chars() {
        let mapped = if ch.is_ascii_alphanumeric() || ch == '-' {
            ch
        } else {
            '-'
        };
        if mapped == '-' {
            if !last_dash {
                out.push('-');
            }
            last_dash = true;
        } else {
            out.push(mapped);
            last_dash = false;
        }
    }
    let normalized = out.trim_matches('-');
    if normalized.len() <= 63 {
        return normalized.to_string();
    }

    let digest = Sha256::digest(instance_key.as_bytes());
    let hash = digest[..6]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let prefix = normalized[..63 - hash.len() - 1].trim_end_matches('-');
    format!("{prefix}-{hash}")
}

fn build_plan(req: &PlanRequest) -> PlanResponse {
    let container_name = sanitize_container_name(&req.instance_key);
    let mut args = vec![
        "run".to_string(),
        "--rm".to_string(),
        "-i".to_string(),
        "--name".to_string(),
        container_name.clone(),
        "--memory".to_string(),
        format!("{}m", req.config.memory_limit_mb),
        "--memory-swap".to_string(),
        format!("{}m", req.config.memory_limit_mb),
    ];

    if req.memory_reservation_mb > 0 {
        args.push("--memory-reservation".to_string());
        args.push(format!("{}m", req.memory_reservation_mb));
    }

    args.extend([
        "--cpus".to_string(),
        format_number(req.config.cpu_limit),
        "--pids-limit".to_string(),
        req.config.pids_limit.to_string(),
        "--read-only".to_string(),
        "--tmpfs".to_string(),
        format!("/tmp:size={}m,noexec,nosuid", req.config.tmp_size_mb),
        "--tmpfs".to_string(),
        "/home/node/.npm:size=64m,nosuid,uid=1000,gid=1000".to_string(),
        "--tmpfs".to_string(),
        "/home/nobody/.local:size=64m,nosuid,uid=65534,gid=65534".to_string(),
        "--security-opt=no-new-privileges".to_string(),
        "--cap-drop=ALL".to_string(),
        "--oom-score-adj".to_string(),
        "500".to_string(),
        "--cgroupns".to_string(),
        "private".to_string(),
        "--log-driver".to_string(),
        "json-file".to_string(),
        "--log-opt".to_string(),
        "max-size=10m".to_string(),
        "--log-opt".to_string(),
        "max-file=3".to_string(),
    ]);

    match req.effective_network_policy.as_str() {
        "none" => {
            args.push("--network".to_string());
            args.push("none".to_string());
        }
        "restricted" | "open" => {
            if !req.network_profile.name.is_empty() {
                args.push("--network".to_string());
                args.push(req.network_profile.name.clone());
            }
        }
        _ => {}
    }

    if req.runtime == "runsc" {
        args.push("--runtime=runsc".to_string());
    }

    for (key, value) in &req.runtime_env {
        args.push("--env".to_string());
        args.push(format!("{key}={}", value.as_str().unwrap_or_default()));
    }

    for key in &req.secret_env_keys {
        args.push("--env".to_string());
        args.push(key.clone());
    }

    args.push(req.image_tag.clone());

    PlanResponse {
        version: VERSION,
        container_name,
        args,
        runtime: req.runtime.clone(),
        control_mode: req.control_mode.clone(),
        effective_network_policy: req.effective_network_policy.clone(),
        network_name: req.network_profile.name.clone(),
        secret_values_in_argv: false,
    }
}

fn format_number(value: f64) -> String {
    let mut rendered = value.to_string();
    if rendered.ends_with(".0") {
        rendered.truncate(rendered.len() - 2);
    }
    rendered
}

fn read_spec_from_env_or_stdin() -> Result<PlanRequest, String> {
    if let Ok(raw) = env::var("SANDBOXD_SPEC_JSON") {
        return serde_json::from_str(&raw).map_err(|err| err.to_string());
    }
    let mut raw = String::new();
    std::io::stdin()
        .read_to_string(&mut raw)
        .map_err(|err| err.to_string())?;
    serde_json::from_str(&raw).map_err(|err| err.to_string())
}

fn run_container() -> Result<i32, String> {
    let req = read_spec_from_env_or_stdin()?;
    let plan = build_plan(&req);
    let mut child = Command::new("docker")
        .args(&plan.args)
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()
        .map_err(|err| format!("failed to spawn docker: {err}"))?;
    let status = child
        .wait()
        .map_err(|err| format!("failed to wait for docker: {err}"))?;
    Ok(status.code().unwrap_or(1))
}

fn print_plan() -> Result<(), String> {
    let req = read_spec_from_env_or_stdin()?;
    let plan = build_plan(&req);
    println!(
        "{}",
        serde_json::to_string(&plan).map_err(|err| err.to_string())?
    );
    Ok(())
}

fn stop_container(container_name: &str) -> serde_json::Value {
    let stop = Command::new("docker")
        .args(["stop", container_name])
        .output();
    let rm = Command::new("docker")
        .args(["rm", "-f", container_name])
        .output();
    json!({
        "stopped": stop.as_ref().map(|o| o.status.success()).unwrap_or(false),
        "removed": rm.as_ref().map(|o| o.status.success()).unwrap_or(false),
        "stopError": stop.err().map(|e| e.to_string()),
        "removeError": rm.err().map(|e| e.to_string()),
    })
}

fn container_status(container_name: &str) -> serde_json::Value {
    let output = Command::new("docker")
        .args(["inspect", "--format={{.State.Running}}", container_name])
        .output();
    match output {
        Ok(out) => json!({
            "containerName": container_name,
            "running": String::from_utf8_lossy(&out.stdout).trim() == "true",
            "exitCode": out.status.code(),
        }),
        Err(err) => json!({
            "containerName": container_name,
            "running": false,
            "error": err.to_string(),
        }),
    }
}

fn posture() -> serde_json::Value {
    json!({
        "version": VERSION,
        "capabilities": {
            "planContainer": true,
            "stdioRunContainer": true,
            "daemonStartContainer": false,
            "stopContainer": true,
            "containerStatus": true
        }
    })
}

fn serve(socket_path: &str) -> Result<(), String> {
    let _ = fs::remove_file(socket_path);
    let listener = UnixListener::bind(socket_path).map_err(|err| err.to_string())?;
    for stream in listener.incoming() {
        match stream {
            Ok(mut stream) => {
                let _ = handle_http(&mut stream);
            }
            Err(err) => eprintln!("sandboxd accept error: {err}"),
        }
    }
    Ok(())
}

fn secure_egress_socket(socket_path: &str, expected_gid: u32) -> Result<(), String> {
    fs::set_permissions(socket_path, fs::Permissions::from_mode(0o660))
        .map_err(|err| format!("failed to secure egress socket: {err}"))?;
    let metadata = fs::metadata(socket_path)
        .map_err(|err| format!("failed to inspect egress socket owner: {err}"))?;
    if metadata.gid() != expected_gid {
        return Err(format!(
            "egress socket inherited gid {}, expected {expected_gid}",
            metadata.gid()
        ));
    }
    Ok(())
}

fn serve_egress(socket_path: &str) -> Result<(), String> {
    let _ = fs::remove_file(socket_path);
    let listener = UnixListener::bind(socket_path).map_err(|err| err.to_string())?;
    secure_egress_socket(socket_path, 999)?;

    for stream in listener.incoming() {
        match stream {
            Ok(mut stream) => {
                let _ = handle_egress_http(&mut stream);
            }
            Err(err) => eprintln!("sandboxd egress accept error: {err}"),
        }
    }
    Ok(())
}

fn validate_network_name(network_name: &str, open: bool) -> Result<(), String> {
    let prefix = if open { "mcp-open-" } else { "mcp-restricted-" };
    if !network_name.starts_with(prefix)
        || network_name.len() <= prefix.len()
        || !network_name
            .chars()
            .all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '-' || ch == '_')
    {
        return Err("invalid gateway network name".to_string());
    }
    Ok(())
}

fn validate_bridge(bridge: &str) -> Result<(), String> {
    let suffix = bridge.strip_prefix("br-").unwrap_or_default();
    if suffix.len() != 12
        || !suffix
            .chars()
            .all(|ch| ch.is_ascii_digit() || ('a'..='f').contains(&ch))
    {
        return Err("invalid bridge interface".to_string());
    }
    Ok(())
}

fn validate_chain(chain: &str) -> Result<(), String> {
    let suffix = chain.strip_prefix("MCP-EGR-").unwrap_or_default();
    if suffix.len() != 16
        || !suffix
            .chars()
            .all(|ch| ch.is_ascii_digit() || ('A'..='F').contains(&ch))
    {
        return Err("invalid egress chain name".to_string());
    }
    Ok(())
}

fn validate_public_ipv4(value: &str) -> Result<(), String> {
    let ip = value
        .parse::<Ipv4Addr>()
        .map_err(|_| "allowed IP must be IPv4".to_string())?;
    let [a, b, c, _d] = ip.octets();
    let prohibited = a == 0
        || a == 10
        || a == 127
        || (a == 100 && (64..=127).contains(&b))
        || (a == 169 && b == 254)
        || (a == 172 && (16..=31).contains(&b))
        || (a == 192 && b == 168)
        || (a == 192 && b == 0 && c == 2)
        || (a == 198 && (b == 18 || b == 19 || (b == 51 && c == 100)))
        || (a == 203 && b == 0 && c == 113)
        || a >= 224;
    if prohibited {
        return Err("allowed IP must be public IPv4".to_string());
    }
    Ok(())
}

fn run_iptables(args: &[&str]) -> Result<(), String> {
    let output = Command::new("iptables")
        .arg("-w")
        .arg("5")
        .args(args)
        .output()
        .map_err(|err| format!("failed to execute iptables: {err}"))?;
    if output.status.success() {
        Ok(())
    } else {
        Err(format!(
            "iptables failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ))
    }
}

fn cleanup_egress_rules(bridge: Option<&str>, chain: &str) -> Result<(), String> {
    validate_chain(chain)?;
    if let Some(bridge) = bridge {
        validate_bridge(bridge)?;
        let _ = run_iptables(&["-D", "FORWARD", "-i", bridge, "-j", chain]);
        // Remove the legacy, incorrectly directed jump if it is present.
        let _ = run_iptables(&["-D", "FORWARD", "-o", bridge, "-j", chain]);
    }
    let _ = run_iptables(&["-F", chain]);
    let _ = run_iptables(&["-X", chain]);
    Ok(())
}

fn apply_egress_rules(req: &EgressApplyRequest) -> Result<(), String> {
    validate_network_name(&req.network_name, req.open)?;
    validate_bridge(&req.bridge_interface)?;
    validate_chain(&req.chain_name)?;
    for ip in &req.allowed_ips {
        validate_public_ipv4(ip)?;
    }

    if run_iptables(&["-N", &req.chain_name]).is_err() {
        run_iptables(&["-F", &req.chain_name])?;
    }
    // A previous direct-enforcement deployment may have left an output-bridge
    // jump. It never represented outbound policy and must not survive migration.
    let _ = run_iptables(&[
        "-D",
        "FORWARD",
        "-o",
        &req.bridge_interface,
        "-j",
        &req.chain_name,
    ]);
    if run_iptables(&[
        "-C",
        "FORWARD",
        "-i",
        &req.bridge_interface,
        "-j",
        &req.chain_name,
    ])
    .is_err()
    {
        run_iptables(&[
            "-I",
            "FORWARD",
            "-i",
            &req.bridge_interface,
            "-j",
            &req.chain_name,
        ])?;
    }

    let result = (|| {
        run_iptables(&[
            "-A",
            &req.chain_name,
            "-p",
            "udp",
            "--dport",
            "53",
            "-j",
            "ACCEPT",
        ])?;
        run_iptables(&[
            "-A",
            &req.chain_name,
            "-p",
            "tcp",
            "--dport",
            "53",
            "-j",
            "ACCEPT",
        ])?;
        for range in BLOCKED_RANGES {
            run_iptables(&["-A", &req.chain_name, "-d", range, "-j", "DROP"])?;
        }
        for ip in &req.allowed_ips {
            run_iptables(&["-A", &req.chain_name, "-d", ip, "-j", "ACCEPT"])?;
        }
        run_iptables(&[
            "-A",
            &req.chain_name,
            "-j",
            if req.open { "ACCEPT" } else { "DROP" },
        ])
    })();

    if result.is_err() {
        let _ = cleanup_egress_rules(Some(&req.bridge_interface), &req.chain_name);
    }
    result
}

fn read_http_request(stream: &mut UnixStream) -> Result<(String, String), String> {
    const MAX_REQUEST_BYTES: usize = 1024 * 1024;
    let mut raw = Vec::with_capacity(4096);
    let mut expected_len: Option<usize> = None;
    let mut header_end: Option<usize> = None;

    loop {
        if raw.len() >= MAX_REQUEST_BYTES {
            return Err("http request too large".to_string());
        }
        let mut chunk = [0_u8; 8192];
        let n = stream.read(&mut chunk).map_err(|err| err.to_string())?;
        if n == 0 {
            break;
        }
        raw.extend_from_slice(&chunk[..n]);

        if header_end.is_none() {
            header_end = raw.windows(4).position(|window| window == b"\r\n\r\n");
            if let Some(end) = header_end {
                let head = String::from_utf8_lossy(&raw[..end]);
                let content_length = head
                    .lines()
                    .find_map(|line| {
                        let (name, value) = line.split_once(':')?;
                        name.eq_ignore_ascii_case("content-length")
                            .then(|| value.trim().parse::<usize>().ok())
                            .flatten()
                    })
                    .unwrap_or(0);
                if content_length > MAX_REQUEST_BYTES.saturating_sub(end + 4) {
                    return Err("http request too large".to_string());
                }
                expected_len = Some(end + 4 + content_length);
            }
        }

        if expected_len.is_some_and(|length| raw.len() >= length) {
            break;
        }
    }

    let end = header_end.ok_or_else(|| "invalid http request".to_string())?;
    let expected = expected_len.unwrap_or(end + 4);
    if raw.len() < expected {
        return Err("incomplete http request body".to_string());
    }
    let head = String::from_utf8(raw[..end].to_vec()).map_err(|err| err.to_string())?;
    let body = String::from_utf8(raw[end + 4..expected].to_vec()).map_err(|err| err.to_string())?;
    Ok((head, body))
}

fn handle_egress_http(stream: &mut UnixStream) -> Result<(), String> {
    let (head, body) = read_http_request(stream)?;
    let request_line = head.lines().next().unwrap_or_default();
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or_default();
    let path = parts.next().unwrap_or_default();

    let (status, payload) = match (method, path) {
        ("GET", "/v1/egress/health") => {
            // Listing the host FORWARD chain is read-only but still requires the
            // NET_ADMIN capability needed by apply/cleanup. Readiness therefore
            // proves both binary availability and the narrow runtime privilege.
            match run_iptables(&["-L", "FORWARD", "-n"]) {
                Ok(()) => (200, json!({ "status": "ok", "iptablesAvailable": true })),
                Err(err) => {
                    eprintln!("sandboxd egress health check failed: {err}");
                    (503, json!({ "error": "iptables_unavailable" }))
                }
            }
        }
        ("POST", "/v1/egress/apply") => match serde_json::from_str::<EgressApplyRequest>(&body) {
            Ok(req) => match apply_egress_rules(&req) {
                Ok(()) => (200, json!({ "enforced": true })),
                Err(err) => (422, json!({ "error": err })),
            },
            Err(err) => (400, json!({ "error": err.to_string() })),
        },
        ("POST", "/v1/egress/cleanup") => {
            match serde_json::from_str::<EgressCleanupRequest>(&body) {
                Ok(req) => match validate_network_name(
                    &req.network_name,
                    req.network_name.starts_with("mcp-open-"),
                )
                .and_then(|_| {
                    cleanup_egress_rules(req.bridge_interface.as_deref(), &req.chain_name)
                }) {
                    Ok(()) => (200, json!({ "cleaned": true })),
                    Err(err) => (422, json!({ "error": err })),
                },
                Err(err) => (400, json!({ "error": err.to_string() })),
            }
        }
        _ => (404, json!({ "error": "not_found" })),
    };

    let body = serde_json::to_string(&payload).map_err(|err| err.to_string())?;
    let status_text = if status == 200 { "OK" } else { "ERROR" };
    let response = format!(
        "HTTP/1.1 {status} {status_text}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    );
    stream
        .write_all(response.as_bytes())
        .map_err(|err| err.to_string())
}

fn handle_http(stream: &mut UnixStream) -> Result<(), String> {
    let (head, body) = read_http_request(stream)?;
    let request_line = head.lines().next().unwrap_or_default();
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or_default();
    let path = parts.next().unwrap_or_default();

    let (status, payload) = match (method, path) {
        ("GET", "/v1/posture") => (200, posture()),
        ("POST", "/v1/plan-container") => match serde_json::from_str::<PlanRequest>(&body) {
            Ok(req) => (200, serde_json::to_value(build_plan(&req)).unwrap()),
            Err(err) => (400, json!({ "error": err.to_string() })),
        },
        ("POST", "/v1/start-container") => (
            501,
            json!({
                "error": "daemon_start_container_not_supported",
                "message": "Use sandboxd run-container so MCP stdio remains attached."
            }),
        ),
        ("POST", "/v1/stop-container") => match serde_json::from_str::<serde_json::Value>(&body) {
            Ok(value) => {
                let name = value
                    .get("containerName")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                (200, stop_container(name))
            }
            Err(err) => (400, json!({ "error": err.to_string() })),
        },
        ("GET", p) if p.starts_with("/v1/container/") && p.ends_with("/status") => {
            let name = p
                .trim_start_matches("/v1/container/")
                .trim_end_matches("/status")
                .trim_matches('/');
            (200, container_status(name))
        }
        _ => (404, json!({ "error": "not_found" })),
    };

    let body = serde_json::to_string(&payload).map_err(|err| err.to_string())?;
    let status_text = if status == 200 { "OK" } else { "ERROR" };
    let response = format!(
        "HTTP/1.1 {status} {status_text}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    );
    stream
        .write_all(response.as_bytes())
        .map_err(|err| err.to_string())
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let result = match args.get(1).map(|s| s.as_str()) {
        Some("plan-container") | Some("plan") => print_plan().map(|_| 0),
        Some("run-container") | Some("run") => run_container(),
        Some("serve") => {
            let socket = args
                .get(2)
                .cloned()
                .or_else(|| env::var("SANDBOXD_SOCKET").ok())
                .unwrap_or_else(|| "/tmp/sandboxd.sock".to_string());
            serve(&socket).map(|_| 0)
        }
        Some("serve-egress") => {
            let socket = args
                .get(2)
                .cloned()
                .or_else(|| env::var("EGRESS_ENFORCER_SOCKET").ok())
                .unwrap_or_else(|| "/tmp/egress-enforcer.sock".to_string());
            serve_egress(&socket).map(|_| 0)
        }
        Some("version") | Some("--version") | Some("-V") => {
            println!("{VERSION}");
            Ok(0)
        }
        _ => {
            eprintln!("usage: sandboxd <plan-container|run-container|serve|serve-egress|version>");
            Ok(2)
        }
    };

    match result {
        Ok(code) => std::process::exit(code),
        Err(err) => {
            eprintln!("sandboxd error: {err}");
            std::process::exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_request() -> PlanRequest {
        PlanRequest {
            instance_key: "0xABC:scope:session-1:server-123".to_string(),
            image_tag: "mcp-img/test:1.0".to_string(),
            runtime: "runc".to_string(),
            control_mode: "proxy".to_string(),
            effective_network_policy: "restricted".to_string(),
            memory_reservation_mb: 0,
            network_profile: NetworkProfile {
                name: "mcp-restricted-abcdef12".to_string(),
                profile_type: "restricted".to_string(),
                egress_allowlist: vec![],
            },
            config: SandboxConfig {
                runtime: "auto".to_string(),
                memory_limit_mb: 512,
                cpu_limit: 1.0,
                pids_limit: 256,
                tmp_size_mb: 64,
                network_policy: "restricted".to_string(),
            },
            runtime_env: {
                let mut env = Map::new();
                env.insert("HOME".to_string(), json!("/tmp"));
                env.insert("TMPDIR".to_string(), json!("/tmp"));
                env
            },
            secret_env_keys: vec!["API_KEY".to_string()],
        }
    }

    #[test]
    fn sanitizes_container_names_like_typescript_path() {
        assert_eq!(
            sanitize_container_name("0xABC:server-123"),
            "0xABC-server-123"
        );
        assert_eq!(sanitize_container_name("foo::bar"), "foo-bar");
        assert_eq!(sanitize_container_name(":foo:"), "foo");
        assert_eq!(
            sanitize_container_name("__anonymous__:server-1"),
            "anonymous-server-1"
        );
        assert_eq!(sanitize_container_name(&"a".repeat(100)).len(), 63);
    }

    #[test]
    fn hashes_long_session_container_names_like_typescript_path() {
        let prefix = format!(
            "0x{}:3883e5df-de92-5c4d-9c09-f4f79a62e22d:session:",
            "a".repeat(40)
        );
        let first = format!("{prefix}0b865020-3c1a-416f-a889-d963c7c46abf");
        let second = format!("{prefix}4f2e755e-5c4a-44e9-b970-4fe0a14107e9");

        assert_eq!(
            sanitize_container_name(&first),
            "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-3883e5d-752f5a44a385"
        );
        assert_ne!(
            sanitize_container_name(&first),
            sanitize_container_name(&second)
        );
    }

    #[test]
    fn plan_keeps_secret_values_out_of_argv() {
        let req = base_request();
        let plan = build_plan(&req);
        assert!(plan.args.contains(&"--read-only".to_string()));
        assert!(plan
            .args
            .contains(&"--security-opt=no-new-privileges".to_string()));
        assert!(plan.args.contains(&"--cap-drop=ALL".to_string()));
        assert!(plan
            .args
            .windows(2)
            .any(|pair| pair == ["--env", "API_KEY"]));
        assert!(!plan.args.iter().any(|arg| arg.contains("sk-")));
    }

    #[test]
    fn plan_uses_open_network_name_for_session_permissive_profiles() {
        let mut req = base_request();
        req.effective_network_policy = "open".to_string();
        req.network_profile.name = "mcp-open-deadbeef".to_string();
        req.network_profile.profile_type = "open".to_string();
        let plan = build_plan(&req);
        assert!(plan
            .args
            .windows(2)
            .any(|pair| pair == ["--network", "mcp-open-deadbeef"]));
    }

    #[test]
    fn plan_preserves_gateway_memory_reservation() {
        let mut raw = serde_json::to_value(base_request()).expect("serialize base request");
        raw["memoryReservationMb"] = json!(256);
        let req: PlanRequest = serde_json::from_value(raw).expect("parse request with reservation");

        let plan = build_plan(&req);

        assert!(plan
            .args
            .windows(2)
            .any(|pair| pair == ["--memory-reservation", "256m"]));
    }

    #[test]
    fn preserves_typescript_runtime_env_insertion_order() {
        let mut req = base_request();
        let mut env = Map::new();
        env.insert("DRPC_API_KEY".to_string(), json!(""));
        env.insert("HOME".to_string(), json!("/tmp"));
        env.insert("npm_config_cache".to_string(), json!("/tmp/.npm"));
        env.insert("PIP_CACHE_DIR".to_string(), json!("/tmp/.cache/pip"));
        env.insert("TMPDIR".to_string(), json!("/tmp"));
        req.runtime_env = env;

        let plan = build_plan(&req);
        let env_values = plan
            .args
            .windows(2)
            .filter_map(|pair| (pair[0] == "--env").then(|| pair[1].clone()))
            .collect::<Vec<_>>();

        assert_eq!(
            &env_values[..5],
            &[
                "DRPC_API_KEY=".to_string(),
                "HOME=/tmp".to_string(),
                "npm_config_cache=/tmp/.npm".to_string(),
                "PIP_CACHE_DIR=/tmp/.cache/pip".to_string(),
                "TMPDIR=/tmp".to_string(),
            ]
        );
    }

    #[test]
    fn accepts_only_expected_gateway_network_and_firewall_identifiers() {
        assert!(validate_network_name("mcp-restricted-kfdb-abcdef12", false).is_ok());
        assert!(validate_network_name("mcp-open-abcdef12", true).is_ok());
        assert!(validate_network_name("bridge0", false).is_err());
        assert!(validate_network_name("mcp-open-abcdef12", false).is_err());
        assert!(validate_bridge("br-abcdef012345").is_ok());
        assert!(validate_bridge("eth0").is_err());
        assert!(validate_chain("MCP-EGR-0123456789ABCDEF").is_ok());
        assert!(validate_chain("FORWARD").is_err());
    }

    #[test]
    fn accepts_public_ipv4_and_rejects_internal_or_metadata_destinations() {
        assert!(validate_public_ipv4("35.190.18.82").is_ok());
        for blocked in [
            "127.0.0.1",
            "10.0.0.1",
            "100.64.0.1",
            "169.254.169.254",
            "172.16.0.1",
            "192.168.0.1",
            "224.0.0.1",
        ] {
            assert!(validate_public_ipv4(blocked).is_err(), "accepted {blocked}");
        }
    }

    #[test]
    fn reads_a_split_http_body_before_dispatching() {
        use std::thread;
        use std::time::Duration;

        let (mut reader, mut writer) = UnixStream::pair().unwrap();
        let body = r#"{"networkName":"mcp-restricted-test"}"#;
        let head = format!(
            "POST /v1/egress/apply HTTP/1.1\r\nContent-Length: {}\r\n\r\n",
            body.len()
        );
        let body_owned = body.to_string();
        let writer_thread = thread::spawn(move || {
            writer.write_all(head.as_bytes()).unwrap();
            thread::sleep(Duration::from_millis(5));
            writer.write_all(body_owned.as_bytes()).unwrap();
        });

        let (observed_head, observed_body) = read_http_request(&mut reader).unwrap();
        writer_thread.join().unwrap();
        assert!(observed_head.starts_with("POST /v1/egress/apply"));
        assert_eq!(observed_body, body);
    }

    #[test]
    fn secures_egress_socket_without_chown_capability() {
        let socket_path =
            std::path::PathBuf::from(format!("/tmp/sandboxd-egress-{}.sock", std::process::id()));
        let _ = fs::remove_file(&socket_path);
        let listener = UnixListener::bind(&socket_path).unwrap();
        let inherited_gid = fs::metadata(&socket_path).unwrap().gid();

        secure_egress_socket(socket_path.to_str().unwrap(), inherited_gid).unwrap();
        let mode = fs::metadata(&socket_path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o660);

        let wrong_gid = if inherited_gid == u32::MAX {
            inherited_gid - 1
        } else {
            inherited_gid + 1
        };
        assert!(
            secure_egress_socket(socket_path.to_str().unwrap(), wrong_gid)
                .unwrap_err()
                .contains("inherited gid")
        );

        drop(listener);
        fs::remove_file(socket_path).unwrap();
    }
}
