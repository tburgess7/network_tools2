use actix_cors::Cors;
use actix_web::{get, web, App, HttpResponse, HttpServer, Responder};
use quick_xml::de::from_str;
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::HashMap;
use std::net::ToSocketAddrs;
use std::process::Command;

// -----------------------------
// Validation functions
// -----------------------------
fn is_valid_ip(ip: &str) -> bool {
    let ip_regex = Regex::new(
        r"^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$",
    )
    .unwrap();
    ip_regex.is_match(ip)
}

fn is_valid_domain(domain: &str) -> bool {
    domain.contains('.') && domain.len() >= 3 && !domain.contains(' ')
}

fn is_private_ip(ip: &str) -> bool {
    let parts: Vec<&str> = ip.split('.').collect();
    if parts.len() != 4 {
        return false;
    }
    if let (Ok(a), Ok(b)) = (parts[0].parse::<u32>(), parts[1].parse::<u32>()) {
        if a == 10 || (a == 172 && (16..=31).contains(&b)) || (a == 192 && b == 168) {
            return true;
        }
    }
    false
}

fn is_allowed_ip(ip: &str) -> bool {
    is_valid_ip(ip) && !ip.starts_with("127.")
}

fn is_allowed_target(target: &str) -> bool {
    (is_valid_ip(target) || is_valid_domain(target))
        && target != "localhost"
        && !target.starts_with("127.")
}

fn resolve_domain_to_ip(domain: &str) -> Option<String> {
    (domain, 0)
        .to_socket_addrs()
        .ok()?
        .find(|addr| addr.is_ipv4())
        .map(|addr| addr.ip().to_string())
}

fn sanitize_domain(domain: &str) -> String {
    if domain.starts_with("www.") {
        domain[4..].to_string()
    } else {
        domain.to_string()
    }
}

// -----------------------------
// Execute a shell command (with whitelist)
// -----------------------------
fn exec(cmd: &str) -> String {
    let allowed_commands = ["ping", "traceroute", "whois", "nslookup", "nmap"];
    let trimmed = cmd.trim();
    if !allowed_commands.iter().any(|&prefix| trimmed.starts_with(prefix)) {
        return "Command not allowed!".to_string();
    }

    let output = Command::new("sh").arg("-c").arg(trimmed).output();
    match output {
        Ok(o) => {
            let stdout = String::from_utf8_lossy(&o.stdout).trim().to_string();
            let stderr = String::from_utf8_lossy(&o.stderr).trim().to_string();
            if stdout.is_empty() && !stderr.is_empty() {
                format!("⚠️ stderr only:\n{}", stderr)
            } else if !stdout.is_empty() {
                stdout
            } else {
                "⚠️ No output captured.".to_string()
            }
        }
        Err(e) => format!("Command failed: {}", e),
    }
}

// -----------------------------
// Helper: Extract the <nmaprun> XML block from raw output
// -----------------------------
fn extract_nmaprun(xml: &str) -> Option<String> {
    if let Some(start) = xml.find("<nmaprun") {
        if let Some(end) = xml.rfind("</nmaprun>") {
            let end = end + "</nmaprun>".len();
            return Some(xml[start..end].to_string());
        }
    }
    None
}

// -----------------------------
// Nmap XML Parsing Structures
// -----------------------------
#[derive(Debug, Deserialize)]
#[serde(rename = "nmaprun")]
struct NmapRun {
    #[serde(rename = "host")]
    host: Option<Host>, // nmap outputs a single host element.
}

#[derive(Debug, Deserialize, Default)]
#[serde(default)]
struct Host {
    ports: Option<Ports>,
}

#[derive(Debug, Deserialize, Default)]
#[serde(default)]
struct Ports {
    #[serde(rename = "port")]
    port: Vec<Port>,
}

#[derive(Debug, Deserialize, Default)]
#[serde(default)]
struct Port {
    #[serde(rename = "@portid")]
    portid: String,
    state: PortState,
}

#[derive(Debug, Deserialize, Default)]
#[serde(default)]
struct PortState {
    #[serde(rename = "@state")]
    state: String,
}

// -----------------------------
// Struct for Parsed Nmap Summary
// -----------------------------
#[derive(Debug, Serialize)]
struct NmapSummary {
    overall_status: String,
    open_ranges: Vec<(i32, i32)>,
    closed_ranges: Vec<(i32, i32)>,
}

fn group_ranges(ports: &Vec<i32>) -> Vec<(i32, i32)> {
    let mut ranges = Vec::new();
    if ports.is_empty() {
        return ranges;
    }
    let mut start = ports[0];
    let mut end = ports[0];
    for &port in ports.iter().skip(1) {
        if port == end + 1 {
            end = port;
        } else {
            ranges.push((start, end));
            start = port;
            end = port;
        }
    }
    ranges.push((start, end));
    ranges
}

/// Parses the raw XML by first extracting the <nmaprun> block.
/// In this version, we do not clean the output.
fn parse_nmap_xml(xml: &str) -> Option<NmapSummary> {
    // Optionally comment out the debug prints.
    // eprintln!("Raw XML:\n{}", xml);

    let extracted = extract_nmaprun(xml)?;
    // eprintln!("Extracted XML:\n{}", extracted);

    let nmaprun: Result<NmapRun, _> = from_str(&extracted);
    match nmaprun {
        Ok(parsed) => {
            // eprintln!("DEBUG: Host present = {}", parsed.host.is_some());
            let host = parsed.host.as_ref()?;
            let ports = host.ports.as_ref()?;
            let mut open_ports = vec![];
            let mut closed_ports = vec![];

            for p in &ports.port {
                let raw_state = p.state.state.trim();
                // eprintln!("DEBUG: Port {}: raw state: '{}'", p.portid, raw_state);
                if let Ok(port_num) = p.portid.parse::<i32>() {
                    if raw_state.eq_ignore_ascii_case("open") {
                        // eprintln!("DEBUG: Port {} detected as open", port_num);
                        open_ports.push(port_num);
                    } else {
                        // eprintln!("DEBUG: Port {} detected as closed", port_num);
                        closed_ports.push(port_num);
                    }
                }
            }

            open_ports.sort();
            closed_ports.sort();
            let open_ranges = group_ranges(&open_ports);
            let closed_ranges = group_ranges(&closed_ports);

            let overall_status = if open_ports.is_empty() && closed_ports.is_empty() {
                "unknown".to_string()
            } else if open_ports.is_empty() {
                "closed".to_string()
            } else {
                "open".to_string()
            };

            Some(NmapSummary {
                overall_status,
                open_ranges,
                closed_ranges,
            })
        }
        Err(_err) => {
            eprintln!("ERROR: Failed to parse XML: {:?}", _err);
            None
        }
    }
}

// -----------------------------
// HTTP Handlers
// -----------------------------
#[get("/ping")]
async fn ping(query: web::Query<HashMap<String, String>>) -> impl Responder {
    let target = match query.get("target") {
        Some(t) => t,
        None => return HttpResponse::BadRequest().body("Missing target parameter"),
    };
    if !is_allowed_target(target) {
        return HttpResponse::BadRequest().body("Invalid parameter: target must be a valid IPv4 address or domain name, and not localhost");
    }
    let command = format!("ping -c 4 {}", target);
    let output = exec(&command);
    HttpResponse::Ok().json(json!({ "result": output }))
}

#[get("/portscan")]
async fn portscan(query: web::Query<HashMap<String, String>>) -> impl Responder {
    let mut target = match query.get("target") {
        Some(t) => t.clone(),
        None => return HttpResponse::BadRequest().body("Missing target parameter"),
    };

    if target == "burgess.services" || target == "www.burgess.services" {
        return HttpResponse::BadRequest().body("Scanning this domain is not allowed");
    }
    if is_valid_ip(&target) {
        if let Some(blocked_ip) = resolve_domain_to_ip("burgess.services") {
            if target == blocked_ip {
                return HttpResponse::BadRequest().body("Scanning this domain is not allowed");
            }
        }
    }
    if !is_valid_ip(&target) && is_valid_domain(&target) {
        if let Some(resolved) = resolve_domain_to_ip(&target) {
            target = resolved;
        } else {
            return HttpResponse::BadRequest().body("Unable to resolve domain name to IPv4 address");
        }
    }
    if !is_allowed_ip(&target) || is_private_ip(&target) {
        return HttpResponse::BadRequest().body("Scanning private IP ranges is not allowed");
    }

    let mut resp = json!({ "target": target });
    if let Some(port) = query.get("port") {
        let port_num: i32 = match port.parse() {
            Ok(n) => n,
            Err(_) => return HttpResponse::BadRequest().body("Invalid port value"),
        };
        if port_num < 1 || port_num > 65535 {
            return HttpResponse::BadRequest().body("Port number out of range (1-65535)");
        }
        let nmap_command = format!("nmap -Pn -sT -p {} {} -oX -", port_num, target);
        let nmap_output = exec(&nmap_command);
        resp["port"] = json!(port_num);
        if let Some(summary) = parse_nmap_xml(&nmap_output) {
            resp["overall_status"] = json!(summary.overall_status);
            resp["open_ranges"] = json!(summary.open_ranges);
            resp["closed_ranges"] = json!(summary.closed_ranges);
        } else {
            resp["overall_status"] = json!("unknown");
            resp["parse_error"] = json!("Failed to parse nmap output");
        }
        resp["nmap_raw"] = json!(nmap_output);
        return HttpResponse::Ok().json(resp);
    } else if let (Some(port_start), Some(port_end)) = (query.get("port_start"), query.get("port_end")) {
        let start_port: i32 = match port_start.parse() {
            Ok(n) => n,
            Err(_) => return HttpResponse::BadRequest().body("Invalid port range values"),
        };
        let end_port: i32 = match port_end.parse() {
            Ok(n) => n,
            Err(_) => return HttpResponse::BadRequest().body("Invalid port range values"),
        };
        if start_port < 1 || end_port > 65535 || start_port > end_port {
            return HttpResponse::BadRequest().body("Port range out of bounds or invalid");
        }
        let nmap_command = format!("nmap -Pn -sT -p {}-{} {} -oX -", start_port, end_port, target);
        let nmap_output = exec(&nmap_command);
        resp["scan_range"] = json!({ "start": start_port, "end": end_port });
        resp["port"] = json!(format!("{}-{}", start_port, end_port));
        resp["nmap_raw"] = json!(nmap_output);
        if let Some(summary) = parse_nmap_xml(&nmap_output) {
            resp["overall_status"] = json!(summary.overall_status);
            resp["open_ranges"] = json!(summary.open_ranges);
            resp["closed_ranges"] = json!(summary.closed_ranges);
        }
        return HttpResponse::Ok().json(resp);
    } else {
        return HttpResponse::BadRequest()
            .body("Missing port parameter. Specify either 'port' or both 'port_start' and 'port_end'");
    }
}

#[get("/traceroute")]
async fn traceroute(query: web::Query<HashMap<String, String>>) -> impl Responder {
    let target = match query.get("target") {
        Some(t) => t,
        None => return HttpResponse::BadRequest().body("Missing target parameter"),
    };
    if !is_allowed_target(target) {
        return HttpResponse::BadRequest().body("Invalid target");
    }
    let command = format!("traceroute {}", target);
    let output = exec(&command);
    let mut lines: Vec<&str> = output.lines().collect();
    if lines.len() > 1 {
        lines[1] = "1 *** RESTRICTED ***";
        if lines.len() > 2 {
            lines[2] = "2 *** RESTRICTED ***";
        }
    }
    let modified_output = lines.join("\n");
    HttpResponse::Ok().json(json!({ "result": modified_output }))
}

#[get("/whois")]
async fn whois(query: web::Query<HashMap<String, String>>) -> impl Responder {
    let target = match query.get("target") {
        Some(t) => t,
        None => return HttpResponse::BadRequest().body("Missing target parameter"),
    };
    if !is_allowed_target(target) {
        return HttpResponse::BadRequest().body("Invalid target");
    }
    let sanitized = sanitize_domain(target);
    let command = format!("whois {}", sanitized);
    let output = exec(&command);
    HttpResponse::Ok().json(json!({ "result": output }))
}

#[get("/nslookup")]
async fn nslookup(query: web::Query<HashMap<String, String>>) -> impl Responder {
    let target = match query.get("target") {
        Some(t) => t,
        None => return HttpResponse::BadRequest().body("Missing target parameter"),
    };
    if !is_allowed_target(target) {
        return HttpResponse::BadRequest().body("Invalid target");
    }
    let command = format!("nslookup {}", target);
    let output = exec(&command);
    let mut filtered_output = String::new();
    let mut header_ended = false;
    for line in output.lines() {
        if !header_ended {
            if line.trim().is_empty() {
                header_ended = true;
            }
            continue;
        }
        filtered_output.push_str(line);
        filtered_output.push('\n');
    }
    HttpResponse::Ok().json(json!({ "result": filtered_output }))
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    HttpServer::new(|| {
        App::new()
            .wrap(
                Cors::default()
                    .allow_any_origin()
                    .allowed_methods(vec!["GET", "POST", "OPTIONS"])
                    .allowed_header(actix_web::http::header::CONTENT_TYPE),
            )
            .service(ping)
            .service(portscan)
            .service(traceroute)
            .service(whois)
            .service(nslookup)
    })
    .bind(("127.0.0.1", 18080))?
    .run()
    .await
}
