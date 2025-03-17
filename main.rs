use actix_cors::Cors;
use actix_web::{get, web, App, HttpResponse, HttpServer, Responder};
use regex::Regex;
use serde_json::json;
use std::collections::HashMap;
use std::net::ToSocketAddrs;
use std::process::Command;

// -----------------------------
// Validation functions
// -----------------------------
fn is_valid_ip(ip: &str) -> bool {
    let ip_regex = Regex::new(r"^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$")
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

    let output = Command::new("sh")
        .arg("-c")
        .arg(trimmed)
        .output();

    match output {
        Ok(o) => String::from_utf8_lossy(&o.stdout).to_string(),
        Err(e) => format!("popen failed: {}", e),
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

    if let (Some(port_start), Some(port_end)) = (query.get("port_start"), query.get("port_end")) {
        let start_port: i32 = port_start.parse().unwrap_or(0);
        let end_port: i32 = port_end.parse().unwrap_or(0);
        if start_port < 1 || end_port > 65535 || start_port > end_port {
            return HttpResponse::BadRequest().body("Port range out of bounds or invalid");
        }
        let nmap_command = format!("nmap -p {}-{} {} -oX -", start_port, end_port, target);
        let nmap_output = exec(&nmap_command);
        resp["nmap_output"] = json!(nmap_output);
        return HttpResponse::Ok().json(resp);
    } else if let Some(port) = query.get("port") {
        let port_num: i32 = port.parse().unwrap_or(0);
        if port_num < 1 || port_num > 65535 {
            return HttpResponse::BadRequest().body("Port number out of range (1-65535)");
        }
        let nmap_command = format!("nmap -p {} {} -oX -", port_num, target);
        let nmap_output = exec(&nmap_command);
        resp["nmap_output"] = json!(nmap_output);
        return HttpResponse::Ok().json(resp);
    } else {
        return HttpResponse::BadRequest().body("Missing port parameter. Specify either 'port' or both 'port_start' and 'port_end'");
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
    // Change this depending on your needs, ex. 0.0.0.0 will bind to all ips, and 127.0.0.1 will restrict access to the localhost
    .bind(("127.0.0.1", 18085))?
    .run()
    .await
}
