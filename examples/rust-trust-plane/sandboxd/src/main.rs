use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use std::env;
use std::fs;
use std::io::{Read, Write};
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

fn sanitize_container_name(instance_key: &str) -> String {
    let mut out = String::new();
    let mut last_dash = false;
    for ch in instance_key.chars() {
        let mapped = if ch.is_ascii_alphanumeric() || ch == '-' { ch } else { '-' };
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
    out.trim_matches('-').chars().take(63).collect()
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
    ];

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
    let stop = Command::new("docker").args(["stop", container_name]).output();
    let rm = Command::new("docker").args(["rm", "-f", container_name]).output();
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

fn handle_http(stream: &mut UnixStream) -> Result<(), String> {
    let mut buf = vec![0_u8; 1024 * 1024];
    let n = stream.read(&mut buf).map_err(|err| err.to_string())?;
    let raw = String::from_utf8_lossy(&buf[..n]);
    let (head, body) = raw
        .split_once("\r\n\r\n")
        .ok_or_else(|| "invalid http request".to_string())?;
    let request_line = head.lines().next().unwrap_or_default();
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or_default();
    let path = parts.next().unwrap_or_default();

    let (status, payload) = match (method, path) {
        ("GET", "/v1/posture") => (200, posture()),
        ("POST", "/v1/plan-container") => match serde_json::from_str::<PlanRequest>(body) {
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
        ("POST", "/v1/stop-container") => match serde_json::from_str::<serde_json::Value>(body) {
            Ok(value) => {
                let name = value.get("containerName").and_then(|v| v.as_str()).unwrap_or("");
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
        Some("version") | Some("--version") | Some("-V") => {
            println!("{VERSION}");
            Ok(0)
        }
        _ => {
            eprintln!("usage: sandboxd <plan-container|run-container|serve|version>");
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
        assert_eq!(sanitize_container_name("0xABC:server-123"), "0xABC-server-123");
        assert_eq!(sanitize_container_name("foo::bar"), "foo-bar");
        assert_eq!(sanitize_container_name(":foo:"), "foo");
        assert_eq!(sanitize_container_name("__anonymous__:server-1"), "anonymous-server-1");
        assert_eq!(sanitize_container_name(&"a".repeat(100)).len(), 63);
    }

    #[test]
    fn plan_keeps_secret_values_out_of_argv() {
        let req = base_request();
        let plan = build_plan(&req);
        assert!(plan.args.contains(&"--read-only".to_string()));
        assert!(plan.args.contains(&"--security-opt=no-new-privileges".to_string()));
        assert!(plan.args.contains(&"--cap-drop=ALL".to_string()));
        assert!(plan.args.windows(2).any(|pair| pair == ["--env", "API_KEY"]));
        assert!(!plan.args.iter().any(|arg| arg.contains("sk-")));
    }

    #[test]
    fn plan_uses_open_network_name_for_session_permissive_profiles() {
        let mut req = base_request();
        req.effective_network_policy = "open".to_string();
        req.network_profile.name = "mcp-open-deadbeef".to_string();
        req.network_profile.profile_type = "open".to_string();
        let plan = build_plan(&req);
        assert!(plan.args.windows(2).any(|pair| pair == ["--network", "mcp-open-deadbeef"]));
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
        let env_values = plan.args
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
}
