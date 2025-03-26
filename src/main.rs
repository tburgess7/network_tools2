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
    if domain.contains(' ') || domain.len() < 3 {
        return false;
    }
    domain.contains('.')
}

fn is_private_ip(ip: &str) -> bool {
    let parts: Vec<&str> = ip.split('.').collect();
    if parts.len() != 4 {
        return false;
    }
    if let (Ok(a), Ok(b)) = (parts[0].parse::<u32>(), parts[1].parse::<u32>()) {
        if a == 10 {
            return true;
        }
        if a == 172 && (16..=31).contains(&b) {
            return true;
        }
        if a == 192 && b == 168 {
            return true;
        }
    }
    false
}

fn is_allowed_ip(ip: &str) -> bool {
    if !is_valid_ip(ip) {
        return false;
    }
    if ip.starts_with("127.") {
        return false;
    }
    true
}

fn is_allowed_target(target: &str) -> bool {
    if !(is_valid_ip(target) || is_valid_domain(target)) {
        return false;
    }
    if target == "localhost" || target.starts_with("127.") {
        return false;
    }
    true
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
        Ok(o) => String::from_utf8_lossy(&o.stdout).to_string(),
        Err(e) => format!("popen failed: {}", e),
    }
}

// -----------------------------
// Nmap XML Parsing Structures
// -----------------------------
#[derive(Debug, Deserialize)]
#[serde(rename = "nmaprun")]
struct NmapRun {
    host: Option<Host>,
}

#[derive(Debug, Deserialize)]
struct Host {
    ports: Option<Ports>,
}

#[derive(Debug, Deserialize)]
struct Ports {
    #[serde(rename = "port")]
    port: Vec<Port>,
}

#[derive(Debug, Deserialize)]
struct Port {
    #[serde(rename = "portid")]
    portid: String,
    state: PortState,
}

#[derive(Debug, Deserialize)]
struct PortState {
    #[serde(rename = "state")]
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

// Group a sorted vector of port numbers into contiguous ranges.
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

// Parse the XML output from nmap into a NmapSummary.
fn parse_nmap_xml(xml: &str) -> Option<NmapSummary> {
    let nmaprun: NmapRun = from_str(xml).ok()?;
    let host = nmaprun.host?;
    let ports = host.ports?;
    let mut open_ports = vec![];
    let mut closed_ports = vec![];

    for p in ports.port {
        if let Ok(port_num) = p.portid.parse::<i32>() {
            if p.state.state == "open" {
                open_ports.push(port_num);
            } else {
                closed_ports.push(port_num);
            }
        }
    }
    open_ports.sort();
    closed_ports.sort();
    let open_ranges = group_ranges(&open_ports);
    let closed_ranges = group_ranges(&closed_ports);
    let overall_status = if open_ports.is_empty() {
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
        return HttpResponse::BadRequest()
            .body("Invalid parameter: target must be a valid IPv4 address or domain name, and not localhost");
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

    // Block scanning for specific domains.
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

    // If target is a domain, resolve it.
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

    // Create a JSON response object.
    let mut resp = json!({ "target": target });

    // If both port_start and port_end are provided.
    if let (Some(port_start), Some(port_end)) = (query.get("port_start"), query.get("port_end")) {
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
        // Execute nmap with XML output.
        let nmap_command = format!("nmap -p {}-{} {} -oX -", start_port, end_port, target);
        let nmap_output = exec(&nmap_command);
        resp["scan_range"] = json!({ "start": start_port, "end": end_port });
        resp["port"] = json!(format!("{}-{}", start_port, end_port));
        resp["nmap_raw"] = json!(nmap_output);

        // Parse the XML output to determine overall status and port ranges.
        if let Some(summary) = parse_nmap_xml(&nmap_output) {
            resp["overall_status"] = json!(summary.overall_status);
            resp["open_ranges"] = json!(summary.open_ranges);
            resp["closed_ranges"] = json!(summary.closed_ranges);
        }
        return HttpResponse::Ok().json(resp);
    }
    // Single port branch.
    else if let Some(port) = query.get("port") {
        let port_num: i32 = match port.parse() {
            Ok(n) => n,
            Err(_) => return HttpResponse::BadRequest().body("Invalid port value"),
        };
        if port_num < 1 || port_num > 65535 {
            return HttpResponse::BadRequest().body("Port number out of range (1-65535)");
        }
        let nmap_command = format!("nmap -p {} {} -oX -", port_num, target);
        let nmap_output = exec(&nmap_command);
        resp["port"] = json!(port_num);
        // Parse the XML for a single port.
        if let Some(summary) = parse_nmap_xml(&nmap_output) {
            resp["overall_status"] = json!(summary.overall_status);
            resp["open_ranges"] = json!(summary.open_ranges);
            resp["closed_ranges"] = json!(summary.closed_ranges);
        }
        resp["nmap_raw"] = json!(nmap_output);
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
