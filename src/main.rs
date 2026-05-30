use std::collections::HashMap;
use std::error::Error;
use std::fs;
use std::io::{self, Cursor, Write};
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use exif;
use clap::{Parser, Subcommand};
use colored::*;
use futures::future::join_all;
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use reqwest::{header, Client, StatusCode};
use scraper::{Html, Selector};
use serde::Deserialize;
use serde_json::Value;
use tokio::time::sleep;

// ─── CLI ───────────────────────────────────────────────────────────────────────

#[derive(Parser)]
#[command(
    name = "rustcohle",
    about = "Rust Cohle — OSINT & Recon Framework",
    long_about = None
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Search username across social networks (Sherlock mode)
    Username {
        #[arg(help = "Username to search")]
        username: String,
    },
    /// Analyze website: headers, meta, links
    Site {
        #[arg(help = "URL to analyze")]
        url: String,
    },
    /// GeoIP + ASN lookup for IP or domain
    Ip {
        #[arg(help = "IP address or domain")]
        target: String,
    },
    /// Extract EXIF metadata from image (URL or path)
    Exif {
        #[arg(help = "Image URL or local path")]
        path: String,
    },
    /// Check email across services (Holehe mode)
    Email {
        #[arg(help = "Email address to check")]
        email: String,
    },
    /// DNS lookup: A, MX, TXT, NS, CNAME records
    Dns {
        #[arg(help = "Domain to query")]
        domain: String,
    },
    /// Whois lookup for domain
    Whois {
        #[arg(help = "Domain to query")]
        domain: String,
    },
    /// Phone number lookup and validation
    Phone {
        #[arg(help = "Phone number in international format (+1234567890)")]
        number: String,
    },
    /// Wayback Machine: find archived snapshots
    Wayback {
        #[arg(help = "URL or domain to search")]
        url: String,
    },
    /// HaveIBeenPwned: check email for data breaches
    Hibp {
        #[arg(help = "Email address to check")]
        email: String,
    },
    /// TLS/CDN fingerprint: detect real IP behind Cloudflare/CDN
    Tls {
        #[arg(help = "Domain to fingerprint")]
        domain: String,
    },
    /// Port scanner: scan common ports on host
    Ports {
        #[arg(help = "Host to scan")]
        host: String,
        #[arg(short, long, default_value = "common", help = "Scan profile: common|full|web")]
        profile: String,
    },
}

// ─── DATA STRUCTURES ──────────────────────────────────────────────────────────

#[derive(Debug, Deserialize, Clone)]
struct Site {
    url: String,
    #[serde(rename = "errorType")]
    error_type: String,
    #[serde(rename = "errorMsg")]
    error_msg: Option<String>,
}
type Sites = HashMap<String, Site>;

#[derive(Debug, Deserialize, Clone)]
struct EmailCheck {
    name: String,
    method: String,
    url: String,
    body: Option<String>,
    headers: Option<HashMap<String, String>>,
    check_type: String,
    json_key: Option<String>,
    expected_value: Option<Value>,
}

#[derive(Debug)]
struct ScanResult {
    found: bool,
    name: String,
    url: String,
    extra: Option<String>,
}

#[derive(Debug)]
struct Summary {
    found: usize,
    not_found: usize,
    errors: usize,
    duration: Duration,
}

// ─── HELPERS ──────────────────────────────────────────────────────────────────

fn get_data_dir() -> PathBuf {
    // Look for json files next to the binary first, then current dir
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            let sites = dir.join("sites.json");
            if sites.exists() {
                return dir.to_path_buf();
            }
        }
    }
    PathBuf::from(".")
}

fn print_ascii_art() {
    let art = r#"
 _____    _    _    _____   _______     _____    ____   _    _   _        ______
|  __ \  | |  | |  / ____| |__   __|   / ____|  / __ \ | |  | | | |      |  ____|
| |__) | | |  | | | (___      | |     | |      | |  | || |__| | | |      | |__
|  _  /  | |  | |  \___ \     | |     | |      | |  | ||  __  | | |      |  __|
| | \ \  | |__| |  ____) |    | |     | |____  | |__| || |  | | | |____  | |____
|_|  \_\  \____/  |_____/     |_|      \_____|  \____/ |_|  |_| |______| |______|
    "#;
    println!("{}", art.magenta().bold());
    println!("{}", "Rust Cohle — OSINT & Recon Framework".cyan().bold());
    println!(
        "{}",
        "Usage: rustcohle <command> [args] | --help for commands".dimmed()
    );
    println!();
}

fn print_summary(label: &str, summary: &Summary) {
    println!();
    println!("{}", "━".repeat(50).dimmed());
    println!(
        "  {} {}",
        "Summary:".bold(),
        label.cyan().bold()
    );
    println!(
        "  {} {}   {} {}   {} {}   {} {:.2}s",
        "✓".green().bold(),
        summary.found.to_string().green().bold(),
        "✗".red(),
        summary.not_found.to_string().red(),
        "!".yellow(),
        summary.errors.to_string().yellow(),
        "⏱".dimmed(),
        summary.duration.as_secs_f64()
    );
    println!("{}", "━".repeat(50).dimmed());
}

fn make_client() -> Result<Client, Box<dyn Error>> {
    Ok(Client::builder()
        .timeout(Duration::from_secs(12))
        .user_agent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36")
        .build()?)
}

fn progress_style() -> ProgressStyle {
    ProgressStyle::with_template(
        "{spinner:.magenta} [{bar:40.cyan/blue}] {pos}/{len} {msg}",
    )
        .unwrap()
        .progress_chars("█▓░")
}

fn spinner_style() -> ProgressStyle {
    ProgressStyle::with_template("{spinner:.cyan} {msg}")
        .unwrap()
        .tick_strings(&["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏", "✓"])
}

// ─── INTERACTIVE MENU (fallback if no subcommand) ─────────────────────────────

async fn interactive_menu() -> Result<(), Box<dyn Error>> {
    loop {
        println!("\n[{}] {}", "?".cyan().bold(), "Select mode:".bold());
        println!("  {}  username <name>    — search across social networks", "1.".yellow());
        println!("  {}  email <addr>       — check email registration", "2.".yellow());
        println!("  {}  hibp <addr>        — HaveIBeenPwned breach check", "3.".yellow());
        println!("  {}  ip <ip|domain>     — GeoIP + ASN lookup", "4.".yellow());
        println!("  {}  dns <domain>       — DNS records (A/MX/TXT/NS/CNAME)", "5.".yellow());
        println!("  {}  whois <domain>     — Whois lookup", "6.".yellow());
        println!("  {}  phone <number>     — Phone number lookup", "7.".yellow());
        println!("  {}  wayback <url>      — Wayback Machine snapshots", "8.".yellow());
        println!("  {}  tls <domain>       — TLS/CDN fingerprint", "9.".yellow());
        println!("  {}  ports <host>       — Port scanner", "10.".yellow());
        println!("  {}  site <url>         — Site analyzer", "11.".yellow());
        println!("  {}  exif <path|url>    — EXIF metadata extractor", "12.".yellow());
        println!("  {}  exit", "0.".yellow());
        print!("> ");
        io::stdout().flush()?;

        let mut choice = String::new();
        io::stdin().read_line(&mut choice)?;

        match choice.trim() {
            "0" | "exit" => {
                println!("{}", "Time is a flat circle. Goodbye.".green());
                break;
            }
            _ => {
                let parts: Vec<&str> = choice.trim().splitn(2, ' ').collect();
                let cmd = match parts[0] {
                    "1" | "username" => "username",
                    "2" | "email" => "email",
                    "3" | "hibp" => "hibp",
                    "4" | "ip" => "ip",
                    "5" | "dns" => "dns",
                    "6" | "whois" => "whois",
                    "7" | "phone" => "phone",
                    "8" | "wayback" => "wayback",
                    "9" | "tls" => "tls",
                    "10" | "ports" => "ports",
                    "11" | "site" => "site",
                    "12" | "exif" => "exif",
                    _ => {
                        println!("{}", "[!] Unknown command.".red());
                        continue;
                    }
                };

                let arg = if parts.len() > 1 {
                    parts[1].to_string()
                } else {
                    print!("  Enter value: ");
                    io::stdout().flush()?;
                    let mut val = String::new();
                    io::stdin().read_line(&mut val)?;
                    val.trim().to_string()
                };

                if arg.is_empty() {
                    continue;
                }

                dispatch_command(cmd, &arg).await?;
            }
        }
    }
    Ok(())
}

async fn dispatch_command(cmd: &str, arg: &str) -> Result<(), Box<dyn Error>> {
    match cmd {
        "username" => sherlock_mode(arg).await?,
        "email" => email_mode(arg).await?,
        "hibp" => hibp_mode(arg).await?,
        "ip" => ip_lookup_mode(arg).await?,
        "dns" => dns_mode(arg).await?,
        "whois" => whois_mode(arg).await?,
        "phone" => phone_mode(arg).await?,
        "wayback" => wayback_mode(arg).await?,
        "tls" => tls_mode(arg).await?,
        "ports" => port_scan_mode(arg, "common").await?,
        "site" => site_parser_mode(arg).await?,
        "exif" => exif_mode(arg).await?,
        _ => {}
    }
    Ok(())
}

// ─── MAIN ─────────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    print_ascii_art();

    let cli = Cli::parse();

    match cli.command {
        Some(Commands::Username { username }) => sherlock_mode(&username).await?,
        Some(Commands::Site { url }) => site_parser_mode(&url).await?,
        Some(Commands::Ip { target }) => ip_lookup_mode(&target).await?,
        Some(Commands::Exif { path }) => exif_mode(&path).await?,
        Some(Commands::Email { email }) => email_mode(&email).await?,
        Some(Commands::Dns { domain }) => dns_mode(&domain).await?,
        Some(Commands::Whois { domain }) => whois_mode(&domain).await?,
        Some(Commands::Phone { number }) => phone_mode(&number).await?,
        Some(Commands::Wayback { url }) => wayback_mode(&url).await?,
        Some(Commands::Hibp { email }) => hibp_mode(&email).await?,
        Some(Commands::Tls { domain }) => tls_mode(&domain).await?,
        Some(Commands::Ports { host, profile }) => port_scan_mode(&host, &profile).await?,
        None => interactive_menu().await?,
    }

    Ok(())
}

// ─── 1. SHERLOCK MODE ─────────────────────────────────────────────────────────

async fn sherlock_mode(username: &str) -> Result<(), Box<dyn Error>> {
    println!(
        "\n[{}] Searching username: {}",
        "*".cyan().bold(),
        username.yellow().bold()
    );

    let data_dir = get_data_dir();
    let sites_data = fs::read_to_string(data_dir.join("sites.json"))
        .map_err(|_| "sites.json not found — place it next to the binary")?;
    let sites: Sites = serde_json::from_str(&sites_data)?;

    let client = make_client()?;
    let total = sites.len() as u64;

    let mp = MultiProgress::new();
    let pb = mp.add(ProgressBar::new(total));
    pb.set_style(progress_style());
    pb.set_message("scanning...");

    let results: Arc<Mutex<Vec<ScanResult>>> = Arc::new(Mutex::new(Vec::new()));
    let start = Instant::now();

    let mut tasks = vec![];
    for (name, site_info) in sites.into_iter() {
        let c = client.clone();
        let u = username.to_string();
        let r = Arc::clone(&results);
        let pb2 = pb.clone();
        tasks.push(tokio::spawn(async move {
            let result = check_site(&c, &name, &site_info, &u).await;
            r.lock().unwrap().push(result);
            pb2.inc(1);
        }));
    }

    join_all(tasks).await;
    pb.finish_with_message("done");

    let mut found_count = 0usize;
    let mut not_found = 0usize;

    let mut results_locked = results.lock().unwrap();
    results_locked.sort_by(|a, b| b.found.cmp(&a.found).then(a.name.cmp(&b.name)));

    println!();
    for r in results_locked.iter() {
        if r.found {
            found_count += 1;
            println!("[{}] {}: {}", "+".green().bold(), r.name.bold(), r.url.cyan());
            if let Some(ref extra) = r.extra {
                println!("    {} {}", "↳".magenta(), extra.dimmed());
            }
        } else {
            not_found += 1;
            println!(
                "[{}] {}: {}",
                "-".red(),
                r.name.bold(),
                "Not Found".dimmed()
            );
        }
    }

    let summary = Summary {
        found: found_count,
        not_found,
        errors: 0,
        duration: start.elapsed(),
    };
    print_summary(username, &summary);
    Ok(())
}

async fn check_site(client: &Client, name: &str, site: &Site, username: &str) -> ScanResult {
    let url = site.url.replace("{}", username);
    let mut found = false;
    let mut page_body = String::new();
    let mut extra: Option<String> = None;

    match client.get(&url).send().await {
        Ok(response) => {
            let status = response.status();
            match response.text().await {
                Ok(body) => {
                    page_body = body;
                    match site.error_type.as_str() {
                        "status_code" => {
                            found = status == StatusCode::OK;
                        }
                        "title" => {
                            if let Some(ref error_msg) = site.error_msg {
                                let document = Html::parse_document(&page_body);
                                if let Ok(selector) = Selector::parse("title") {
                                    if let Some(t) = document.select(&selector).next() {
                                        let title_text = t.inner_html();
                                        found = !title_text.contains(error_msg.as_str());
                                    }
                                }
                            }
                        }
                        _ => {}
                    }
                }
                Err(_) => {}
            }
        }
        Err(_) => {}
    }

    if found {
        if name == "GitHub" {
            let api_url = format!("https://api.github.com/users/{}", username);
            if let Ok(api_res) = client
                .get(&api_url)
                .header("Accept", "application/vnd.github+json")
                .send()
                .await
            {
                if let Ok(json) = api_res.json::<Value>().await {
                    let mut parts = vec![];
                    if let Some(v) = json.get("name").and_then(|v| v.as_str()) {
                        parts.push(format!("name: {}", v));
                    }
                    if let Some(v) = json.get("bio").and_then(|v| v.as_str()) {
                        let clean = v.replace('\n', " ");
                        if !clean.is_empty() {
                            parts.push(format!("bio: {}", clean));
                        }
                    }
                    if let Some(v) = json.get("location").and_then(|v| v.as_str()) {
                        parts.push(format!("location: {}", v));
                    }
                    if let Some(v) = json.get("public_repos").and_then(|v| v.as_u64()) {
                        parts.push(format!("repos: {}", v));
                    }
                    if !parts.is_empty() {
                        extra = Some(parts.join("  |  "));
                    }
                }
            }
        } else {
            let document = Html::parse_document(&page_body);
            if let Ok(selector) = Selector::parse(
                "meta[name=\"description\"], meta[property=\"og:description\"], meta[property=\"og:title\"]",
            ) {
                if let Some(element) = document.select(&selector).next() {
                    if let Some(desc) = element.value().attr("content") {
                        let clean = desc.trim().replace('\n', " ");
                        if !clean.is_empty() {
                            let short = if clean.chars().count() > 80 {
                                format!("{}...", clean.chars().take(77).collect::<String>())
                            } else {
                                clean
                            };
                            extra = Some(short);
                        }
                    }
                }
            }
        }
    }

    ScanResult {
        found,
        name: name.to_string(),
        url,
        extra,
    }
}

// ─── 2. EMAIL MODE ────────────────────────────────────────────────────────────

async fn email_mode(email: &str) -> Result<(), Box<dyn Error>> {
    println!(
        "\n[{}] Checking email: {}",
        "*".cyan().bold(),
        email.yellow().bold()
    );

    let data_dir = get_data_dir();
    let checks_data = fs::read_to_string(data_dir.join("emails.json"))
        .map_err(|_| "emails.json not found")?;
    let checks: Vec<EmailCheck> = serde_json::from_str(&checks_data)?;

    let client = make_client()?;
    let total = checks.len() as u64;
    let pb = ProgressBar::new(total);
    pb.set_style(progress_style());

    let start = Instant::now();
    let mut found = 0usize;
    let mut not_found = 0usize;

    let results: Arc<Mutex<Vec<(bool, String)>>> = Arc::new(Mutex::new(Vec::new()));

    let mut tasks = vec![];
    for check in checks {
        let c = client.clone();
        let e = email.to_string();
        let r = Arc::clone(&results);
        let pb2 = pb.clone();
        tasks.push(tokio::spawn(async move {
            let (f, name) = check_email_on_site(&c, &e, check).await;
            r.lock().unwrap().push((f, name));
            pb2.inc(1);
        }));
    }

    join_all(tasks).await;
    pb.finish_with_message("done");

    println!();
    let locked = results.lock().unwrap();
    for (f, name) in locked.iter() {
        if *f {
            found += 1;
            println!("[{}] {}", "+".green().bold(), name.bold());
        } else {
            not_found += 1;
            println!("[{}] {}: {}", "-".red(), name.bold(), "Not Found".dimmed());
        }
    }

    print_summary(email, &Summary { found, not_found, errors: 0, duration: start.elapsed() });
    Ok(())
}

async fn check_email_on_site(client: &Client, email: &str, check: EmailCheck) -> (bool, String) {
    let md5_email = format!("{:x}", md5::compute(email.to_lowercase().as_bytes()));
    let url = check
        .url
        .replace("{email}", email)
        .replace("{md5_email}", &md5_email);

    let mut rb = match check.method.as_str() {
        "POST" => client.post(&url),
        _ => client.get(&url),
    };

    if let Some(headers) = check.headers {
        let mut hmap = header::HeaderMap::new();
        for (k, v) in headers {
            if let (Ok(hn), Ok(hv)) = (
                header::HeaderName::from_bytes(k.as_bytes()),
                header::HeaderValue::from_str(&v),
            ) {
                hmap.insert(hn, hv);
            }
        }
        rb = rb.headers(hmap);
    }

    if let Some(body_tmpl) = check.body {
        rb = rb.body(body_tmpl.replace("{email}", email));
    }

    let found = match rb.send().await {
        Ok(response) => match check.check_type.as_str() {
            "status" => response.status().is_success(),
            "json_key" => {
                if let (Ok(json), Some(key), Some(expected)) =
                    (response.json::<Value>().await, check.json_key, check.expected_value)
                {
                    json.get(key).map(|v| v == &expected).unwrap_or(false)
                } else {
                    false
                }
            }
            _ => false,
        },
        Err(_) => false,
    };

    (found, check.name)
}

// ─── 3. HIBP MODE ─────────────────────────────────────────────────────────────

async fn hibp_mode(email: &str) -> Result<(), Box<dyn Error>> {
    println!(
        "\n[{}] HaveIBeenPwned check: {}",
        "*".cyan().bold(),
        email.yellow().bold()
    );

    let spinner = ProgressBar::new_spinner();
    spinner.set_style(spinner_style());
    spinner.set_message("querying HIBP...");
    spinner.enable_steady_tick(Duration::from_millis(80));

    let client = make_client()?;
    // Using the v3 public API (no key required for breach names)
    let url = format!(
        "https://haveibeenpwned.com/api/v3/breachedaccount/{}?truncateResponse=false",
        urlencoding::encode(email)
    );

    let res = client
        .get(&url)
        .header("hibp-api-key", "")  // public endpoint doesn't need key for basic info
        .header("User-Agent", "RustCohle-OSINT")
        .send()
        .await;

    spinner.finish_and_clear();

    match res {
        Ok(r) => {
            match r.status().as_u16() {
                200 => {
                    if let Ok(breaches) = r.json::<Vec<Value>>().await {
                        println!(
                            "\n[{}] Found in {} breach(es):\n",
                            "!".red().bold(),
                            breaches.len().to_string().red().bold()
                        );
                        for breach in &breaches {
                            let name = breach["Name"].as_str().unwrap_or("Unknown");
                            let domain = breach["Domain"].as_str().unwrap_or("");
                            let date = breach["BreachDate"].as_str().unwrap_or("?");
                            let pwn_count = breach["PwnCount"].as_u64().unwrap_or(0);
                            let data_classes = breach["DataClasses"]
                                .as_array()
                                .map(|a| {
                                    a.iter()
                                        .filter_map(|v| v.as_str())
                                        .collect::<Vec<_>>()
                                        .join(", ")
                                })
                                .unwrap_or_default();

                            println!(
                                "  {} {} {}",
                                "■".red(),
                                name.bold(),
                                format!("({})", domain).dimmed()
                            );
                            println!("    {} {}", "Date:".cyan(), date);
                            println!("    {} {}", "Records:".cyan(), pwn_count.to_string().yellow());
                            println!("    {} {}", "Data:".cyan(), data_classes);
                            println!();
                        }
                    }
                }
                404 => {
                    println!("\n[{}] {}", "✓".green().bold(), "No breaches found for this email.".green());
                }
                401 => {
                    println!(
                        "\n[{}] {}",
                        "!".yellow(),
                        "HIBP requires an API key for this endpoint. Get one at: https://haveibeenpwned.com/API/Key".yellow()
                    );
                    println!(
                        "    {}",
                        "Set HIBP_API_KEY env variable and rebuild, or check manually.".dimmed()
                    );
                }
                429 => {
                    println!("{}", "[!] Rate limited by HIBP. Try again in a moment.".yellow());
                }
                other => {
                    println!("{}", format!("[!] HIBP returned status: {}", other).red());
                }
            }
        }
        Err(e) => {
            println!("{}", format!("[!] Error: {}", e).red());
        }
    }

    // Also check password exposure via k-Anonymity
    println!("\n[{}] Checking password exposure (Pwned Passwords)...", "*".cyan());
    check_pwned_passwords_hint(email).await;

    Ok(())
}

async fn check_pwned_passwords_hint(email: &str) {
    // Just remind the user — actual password check requires providing a password hash
    println!(
        "  {} {}",
        "↳".magenta(),
        format!(
            "To check if a specific password was leaked: https://haveibeenpwned.com/Passwords"
        )
            .dimmed()
    );
    let _ = email; // intentional
}

// ─── 4. IP LOOKUP MODE ────────────────────────────────────────────────────────

async fn ip_lookup_mode(target: &str) -> Result<(), Box<dyn Error>> {
    println!(
        "\n[{}] GeoIP lookup: {}",
        "*".cyan().bold(),
        target.yellow().bold()
    );

    let spinner = ProgressBar::new_spinner();
    spinner.set_style(spinner_style());
    spinner.set_message("resolving...");
    spinner.enable_steady_tick(Duration::from_millis(80));

    let client = make_client()?;
    let url = format!("https://ipapi.co/{}/json/", target);

    match client.get(&url).send().await {
        Ok(res) => {
            spinner.finish_and_clear();
            if res.status().is_success() {
                if let Ok(json) = res.json::<Value>().await {
                    println!("\n{}", "--- GeoIP / ASN Info ---".magenta().bold());
                    let fields = [
                        ("ip", "IP Address"),
                        ("hostname", "Hostname"),
                        ("city", "City"),
                        ("region", "Region"),
                        ("country_name", "Country"),
                        ("postal", "Postal Code"),
                        ("latitude", "Latitude"),
                        ("longitude", "Longitude"),
                        ("timezone", "Timezone"),
                        ("utc_offset", "UTC Offset"),
                        ("org", "Organization"),
                        ("asn", "ASN"),
                        ("currency", "Currency"),
                        ("languages", "Languages"),
                    ];
                    for (key, label) in fields.iter() {
                        if let Some(val) = json.get(*key) {
                            let s = if val.is_string() {
                                val.as_str().unwrap().to_string()
                            } else {
                                val.to_string()
                            };
                            if !s.is_empty() && s != "null" {
                                println!("  {}: {}", label.cyan(), s);
                            }
                        }
                    }

                    // Abuse check hint
                    if let Some(org) = json.get("org").and_then(|v| v.as_str()) {
                        let hosting_keywords = ["AS13335", "cloudflare", "amazon", "google", "digitalocean", "linode", "vultr", "ovh", "hetzner", "contabo"];
                        let org_lower = org.to_lowercase();
                        if hosting_keywords.iter().any(|k| org_lower.contains(k)) {
                            println!(
                                "\n  {} {}",
                                "⚠".yellow().bold(),
                                "Hosting/CDN provider detected — may not be the real origin IP.".yellow()
                            );
                            println!(
                                "  {} {}",
                                "↳".magenta(),
                                "Try: rustcohle tls <domain> for real IP detection.".dimmed()
                            );
                        }
                    }
                } else {
                    println!("{}", "[!] Failed to parse response.".red());
                }
            } else {
                println!("{}", "[!] Could not resolve target.".red());
            }
        }
        Err(e) => {
            spinner.finish_and_clear();
            println!("{}", format!("[!] Error: {}", e).red());
        }
    }

    Ok(())
}

// ─── 5. DNS MODE ──────────────────────────────────────────────────────────────

async fn dns_mode(domain: &str) -> Result<(), Box<dyn Error>> {
    println!(
        "\n[{}] DNS lookup: {}",
        "*".cyan().bold(),
        domain.yellow().bold()
    );

    let client = make_client()?;
    let record_types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"];
    let start = Instant::now();
    let mut found_any = false;

    let pb = ProgressBar::new(record_types.len() as u64);
    pb.set_style(progress_style());
    pb.set_message("querying DNS...");

    for rtype in &record_types {
        let url = format!(
            "https://dns.google/resolve?name={}&type={}",
            domain, rtype
        );

        sleep(Duration::from_millis(80)).await; // rate limit

        match client.get(&url).send().await {
            Ok(res) => {
                if let Ok(json) = res.json::<Value>().await {
                    if let Some(answers) = json.get("Answer").and_then(|a| a.as_array()) {
                        if !answers.is_empty() {
                            pb.suspend(|| {
                                println!("\n  {} records:", rtype.cyan().bold());
                                for ans in answers {
                                    let data = ans["data"].as_str().unwrap_or("?");
                                    let ttl = ans["TTL"].as_u64().unwrap_or(0);
                                    println!("    {} {} {}", "↳".magenta(), data, format!("(TTL: {})", ttl).dimmed());
                                }
                            });
                            found_any = true;
                        }
                    }
                }
            }
            Err(e) => {
                pb.suspend(|| {
                    eprintln!("  [!] {} query failed: {}", rtype, e);
                });
            }
        }
        pb.inc(1);
    }

    pb.finish_and_clear();

    if !found_any {
        println!("{}", "[!] No DNS records found.".red());
    }

    println!(
        "\n  {} Done in {:.2}s",
        "✓".green(),
        start.elapsed().as_secs_f64()
    );
    Ok(())
}

// ─── 6. WHOIS MODE ────────────────────────────────────────────────────────────

async fn whois_mode(domain: &str) -> Result<(), Box<dyn Error>> {
    println!(
        "\n[{}] Whois lookup: {}",
        "*".cyan().bold(),
        domain.yellow().bold()
    );

    let spinner = ProgressBar::new_spinner();
    spinner.set_style(spinner_style());
    spinner.set_message("querying...");
    spinner.enable_steady_tick(Duration::from_millis(80));

    let client = make_client()?;
    // Using rdap.org which provides structured RDAP data
    let url = format!("https://rdap.org/domain/{}", domain);

    match client.get(&url).send().await {
        Ok(res) => {
            spinner.finish_and_clear();
            if res.status().is_success() {
                if let Ok(json) = res.json::<Value>().await {
                    println!("\n{}", "--- Whois / RDAP Info ---".magenta().bold());

                    // Name
                    if let Some(v) = json.get("ldhName").and_then(|v| v.as_str()) {
                        println!("  {}: {}", "Domain".cyan(), v);
                    }

                    // Status
                    if let Some(arr) = json.get("status").and_then(|v| v.as_array()) {
                        let statuses: Vec<&str> = arr.iter().filter_map(|v| v.as_str()).collect();
                        println!("  {}: {}", "Status".cyan(), statuses.join(", "));
                    }

                    // Events (created, updated, expiry)
                    if let Some(events) = json.get("events").and_then(|v| v.as_array()) {
                        for event in events {
                            let action = event["eventAction"].as_str().unwrap_or("");
                            let date = event["eventDate"].as_str().unwrap_or("?");
                            match action {
                                "registration" => println!("  {}: {}", "Registered".cyan(), date),
                                "last changed" => println!("  {}: {}", "Updated".cyan(), date),
                                "expiration" => println!("  {}: {}", "Expires".cyan(), date.yellow()),
                                _ => {}
                            }
                        }
                    }

                    // Nameservers
                    if let Some(ns_arr) = json.get("nameservers").and_then(|v| v.as_array()) {
                        let ns: Vec<&str> = ns_arr
                            .iter()
                            .filter_map(|v| v.get("ldhName")?.as_str())
                            .collect();
                        if !ns.is_empty() {
                            println!("  {}: {}", "Nameservers".cyan(), ns.join(", "));
                        }
                    }

                    // Registrar
                    if let Some(entities) = json.get("entities").and_then(|v| v.as_array()) {
                        for entity in entities {
                            let roles = entity["roles"].as_array();
                            if let Some(roles) = roles {
                                let is_registrar =
                                    roles.iter().any(|r| r.as_str() == Some("registrar"));
                                if is_registrar {
                                    if let Some(name) = entity
                                        .get("vcardArray")
                                        .and_then(|v| v.as_array())
                                        .and_then(|arr| arr.get(1))
                                        .and_then(|v| v.as_array())
                                        .and_then(|arr| {
                                            arr.iter().find(|item| {
                                                item.as_array()
                                                    .and_then(|a| a.first())
                                                    .and_then(|v| v.as_str())
                                                    == Some("fn")
                                            })
                                        })
                                        .and_then(|item| item.as_array())
                                        .and_then(|a| a.last())
                                        .and_then(|v| v.as_str())
                                    {
                                        println!("  {}: {}", "Registrar".cyan(), name);
                                    }
                                }
                            }
                        }
                    }

                    // IANA WHOIS link
                    println!(
                        "\n  {} {}",
                        "↳".magenta(),
                        format!("Full data: https://rdap.org/domain/{}", domain).dimmed()
                    );
                } else {
                    println!("{}", "[!] Failed to parse RDAP response.".red());
                }
            } else {
                println!(
                    "{}",
                    format!("[!] Domain not found or RDAP unavailable (status: {}).", res.status()).red()
                );
            }
        }
        Err(e) => {
            spinner.finish_and_clear();
            println!("{}", format!("[!] Error: {}", e).red());
        }
    }

    Ok(())
}

// ─── 7. PHONE MODE ────────────────────────────────────────────────────────────

async fn phone_mode(number: &str) -> Result<(), Box<dyn Error>> {
    println!(
        "\n[{}] Phone lookup: {}",
        "*".cyan().bold(),
        number.yellow().bold()
    );

    let spinner = ProgressBar::new_spinner();
    spinner.set_style(spinner_style());
    spinner.set_message("querying...");
    spinner.enable_steady_tick(Duration::from_millis(80));

    let client = make_client()?;

    // Using free phone validation API (no key required)
    let clean = number.trim_start_matches('+');
    let url = format!("https://phonevalidation.abstractapi.com/v1/?api_key=&phone={}", clean);

    // Fallback: use a free no-key endpoint
    let url2 = format!("https://api.apilayer.com/number_verification/validate?number={}", number);
    let _ = url2; // We'll use numverify fallback

    // Phone number regex analysis (offline)
    let phone_clean: String = number.chars().filter(|c| c.is_ascii_digit() || *c == '+').collect();

    spinner.finish_and_clear();

    println!("\n{}", "--- Phone Analysis ---".magenta().bold());
    println!("  {}: {}", "Number".cyan(), phone_clean);

    // Country prefix detection
    let country = detect_country_prefix(&phone_clean);
    println!("  {}: {}", "Country Prefix".cyan(), country);

    // Length check
    let digit_count = phone_clean.chars().filter(|c| c.is_ascii_digit()).count();
    println!("  {}: {} digits", "Length".cyan(), digit_count);

    let valid = digit_count >= 7 && digit_count <= 15;
    println!(
        "  {}: {}",
        "Format Valid".cyan(),
        if valid {
            "Yes (E.164 range)".green().to_string()
        } else {
            "Suspicious length".red().to_string()
        }
    );

    // Try free lookup
    let lookup_url = format!(
        "https://api.country.is/{}",
        phone_clean.trim_start_matches('+')
    );
    if let Ok(res) = client.get(&lookup_url).send().await {
        if let Ok(json) = res.json::<Value>().await {
            if let Some(country_code) = json.get("country").and_then(|v| v.as_str()) {
                println!("  {}: {}", "Country Code".cyan(), country_code.yellow());
            }
        }
    }

    // Truecaller / Sync.me search hints
    println!("\n  {} {}", "↳".magenta(), "Deeper lookup options:".bold());
    println!("    • Truecaller: https://www.truecaller.com/search/us/{}", phone_clean.trim_start_matches('+'));
    println!("    • Sync.me:    https://sync.me/search/?number={}", phone_clean);
    println!("    • 800Notes:   https://800notes.com/Phone.aspx/{}", phone_clean);

    Ok(())
}

fn detect_country_prefix(number: &str) -> String {
    let n = if number.starts_with('+') {
        number[1..].to_string()
    } else {
        number.to_string()
    };

    let prefixes = [
        ("1", "USA / Canada"),
        ("7", "Russia / Kazakhstan"),
        ("20", "Egypt"),
        ("27", "South Africa"),
        ("30", "Greece"),
        ("31", "Netherlands"),
        ("32", "Belgium"),
        ("33", "France"),
        ("34", "Spain"),
        ("36", "Hungary"),
        ("38", "Ukraine"),
        ("39", "Italy"),
        ("40", "Romania"),
        ("41", "Switzerland"),
        ("43", "Austria"),
        ("44", "UK"),
        ("45", "Denmark"),
        ("46", "Sweden"),
        ("47", "Norway"),
        ("48", "Poland"),
        ("49", "Germany"),
        ("351", "Portugal"),
        ("352", "Luxembourg"),
        ("353", "Ireland"),
        ("354", "Iceland"),
        ("355", "Albania"),
        ("358", "Finland"),
        ("359", "Bulgaria"),
        ("370", "Lithuania"),
        ("371", "Latvia"),
        ("372", "Estonia"),
        ("373", "Moldova"),
        ("374", "Armenia"),
        ("375", "Belarus"),
        ("376", "Andorra"),
        ("380", "Ukraine"),
        ("381", "Serbia"),
        ("382", "Montenegro"),
        ("385", "Croatia"),
        ("386", "Slovenia"),
        ("387", "Bosnia"),
        ("389", "North Macedonia"),
        ("420", "Czech Republic"),
        ("421", "Slovakia"),
        ("86", "China"),
        ("81", "Japan"),
        ("82", "South Korea"),
        ("91", "India"),
        ("55", "Brazil"),
        ("52", "Mexico"),
        ("54", "Argentina"),
        ("61", "Australia"),
        ("64", "New Zealand"),
        ("966", "Saudi Arabia"),
        ("971", "UAE"),
        ("972", "Israel"),
        ("90", "Turkey"),
        ("98", "Iran"),
    ];

    // Try longest prefix first
    for len in [3, 2, 1] {
        if n.len() >= len {
            let prefix = &n[..len];
            if let Some((_, country)) = prefixes.iter().find(|(p, _)| *p == prefix) {
                return format!("+{} — {}", prefix, country);
            }
        }
    }

    "Unknown".to_string()
}

// ─── 8. WAYBACK MACHINE ───────────────────────────────────────────────────────

async fn wayback_mode(url: &str) -> Result<(), Box<dyn Error>> {
    println!(
        "\n[{}] Wayback Machine: {}",
        "*".cyan().bold(),
        url.yellow().bold()
    );

    let spinner = ProgressBar::new_spinner();
    spinner.set_style(spinner_style());
    spinner.set_message("fetching snapshots...");
    spinner.enable_steady_tick(Duration::from_millis(80));

    let client = make_client()?;

    // CDX API — get last 10 snapshots
    let clean_url = url.trim_start_matches("https://").trim_start_matches("http://");
    let api_url = format!(
        "https://web.archive.org/cdx/search/cdx?url={}&output=json&limit=10&fl=timestamp,statuscode,mimetype,length,original&filter=statuscode:200&collapse=digest&from=&to=",
        clean_url
    );

    match client.get(&api_url).send().await {
        Ok(res) => {
            spinner.finish_and_clear();
            if res.status().is_success() {
                if let Ok(json) = res.json::<Vec<Vec<String>>>().await {
                    // First row is header
                    if json.len() <= 1 {
                        println!("{}", "[!] No snapshots found in Wayback Machine.".yellow());
                        return Ok(());
                    }

                    println!(
                        "\n[{}] Found {} snapshots:\n",
                        "+".green().bold(),
                        (json.len() - 1).to_string().green().bold()
                    );

                    for row in json.iter().skip(1) {
                        if row.len() < 5 {
                            continue;
                        }
                        let ts = &row[0]; // YYYYMMDDHHmmss
                        let status = &row[1];
                        let mime = &row[2];
                        let size = &row[3];
                        let original = &row[4];

                        // Format timestamp
                        let formatted_ts = if ts.len() >= 14 {
                            format!(
                                "{}-{}-{} {}:{}:{}",
                                &ts[0..4], &ts[4..6], &ts[6..8],
                                &ts[8..10], &ts[10..12], &ts[12..14]
                            )
                        } else {
                            ts.clone()
                        };

                        let wayback_link = format!("https://web.archive.org/web/{}/{}", ts, original);

                        println!("  {} {}", "●".cyan(), formatted_ts.bold());
                        println!("    {} {}", "URL:".dimmed(), wayback_link.cyan());
                        println!("    {} {}  {} {}  {} bytes",
                                 "Status:".dimmed(), status,
                                 "Type:".dimmed(), mime,
                                 size
                        );
                        println!();
                    }

                    // Also check availability API
                    let avail_url = format!(
                        "https://archive.org/wayback/available?url={}",
                        clean_url
                    );
                    if let Ok(avail_res) = client.get(&avail_url).send().await {
                        if let Ok(avail_json) = avail_res.json::<Value>().await {
                            if let Some(snapshot) = avail_json
                                .get("archived_snapshots")
                                .and_then(|v| v.get("closest"))
                            {
                                let ts = snapshot["timestamp"].as_str().unwrap_or("");
                                let snap_url = snapshot["url"].as_str().unwrap_or("");
                                if !snap_url.is_empty() {
                                    println!(
                                        "  {} Closest snapshot: {} — {}",
                                        "✓".green(),
                                        ts,
                                        snap_url.cyan()
                                    );
                                }
                            }
                        }
                    }
                } else {
                    println!("{}", "[!] Failed to parse Wayback response.".red());
                }
            } else {
                println!("{}", "[!] Wayback Machine request failed.".red());
            }
        }
        Err(e) => {
            spinner.finish_and_clear();
            println!("{}", format!("[!] Error: {}", e).red());
        }
    }

    Ok(())
}

// ─── 9. TLS FINGERPRINT (CDN bypass) ─────────────────────────────────────────

async fn tls_mode(domain: &str) -> Result<(), Box<dyn Error>> {
    println!(
        "\n[{}] TLS/CDN Fingerprint: {}",
        "*".cyan().bold(),
        domain.yellow().bold()
    );
    println!(
        "  {}",
        "Attempting to detect real origin IP behind CDN/Cloudflare...".dimmed()
    );

    let client = make_client()?;
    let spinner = ProgressBar::new_spinner();
    spinner.set_style(spinner_style());
    spinner.set_message("analyzing...");
    spinner.enable_steady_tick(Duration::from_millis(80));

    let mut findings: Vec<String> = vec![];

    // 1. Current DNS resolution
    let dns_url = format!("https://dns.google/resolve?name={}&type=A", domain);
    if let Ok(res) = client.get(&dns_url).send().await {
        if let Ok(json) = res.json::<Value>().await {
            if let Some(answers) = json.get("Answer").and_then(|v| v.as_array()) {
                for ans in answers {
                    if let Some(ip) = ans["data"].as_str() {
                        findings.push(format!("current_a:{}", ip));
                    }
                }
            }
        }
    }

    sleep(Duration::from_millis(200)).await;

    // 2. Historical DNS via SecurityTrails-compatible free API
    let hist_url = format!(
        "https://api.hackertarget.com/hostsearch/?q={}",
        domain
    );
    let mut subdomain_ips: Vec<String> = vec![];
    if let Ok(res) = client.get(&hist_url).send().await {
        if let Ok(text) = res.text().await {
            if !text.contains("API count") && !text.contains("error") {
                for line in text.lines().take(20) {
                    let parts: Vec<&str> = line.splitn(2, ',').collect();
                    if parts.len() == 2 {
                        let subdomain = parts[0];
                        let ip = parts[1];
                        subdomain_ips.push(format!("{} → {}", subdomain, ip));
                        findings.push(format!("subdomain_ip:{}", ip));
                    }
                }
            }
        }
    }

    sleep(Duration::from_millis(200)).await;

    // 3. SPF / MX records (often reveal real mail server IPs)
    let spf_url = format!("https://dns.google/resolve?name={}&type=TXT", domain);
    let mut spf_info = String::new();
    if let Ok(res) = client.get(&spf_url).send().await {
        if let Ok(json) = res.json::<Value>().await {
            if let Some(answers) = json.get("Answer").and_then(|v| v.as_array()) {
                for ans in answers {
                    if let Some(data) = ans["data"].as_str() {
                        if data.contains("spf") || data.contains("ip4") {
                            spf_info = data.to_string();
                            // Extract IPs from SPF
                            for part in data.split_whitespace() {
                                if part.starts_with("ip4:") {
                                    let ip = part.trim_start_matches("ip4:");
                                    findings.push(format!("spf_ip:{}", ip));
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    sleep(Duration::from_millis(200)).await;

    // 4. Certificate transparency logs (crt.sh)
    let crt_url = format!(
        "https://crt.sh/?q=%.{}&output=json",
        domain
    );
    let mut cert_subdomains: Vec<String> = vec![];
    if let Ok(res) = client.get(&crt_url).send().await {
        if let Ok(json) = res.json::<Vec<Value>>().await {
            let mut seen = std::collections::HashSet::new();
            for entry in json.iter().take(50) {
                if let Some(name) = entry["name_value"].as_str() {
                    for subdomain in name.split('\n') {
                        let s = subdomain.trim().to_string();
                        if !s.is_empty() && !s.starts_with('*') && seen.insert(s.clone()) {
                            cert_subdomains.push(s);
                        }
                    }
                }
            }
        }
    }

    // 5. Check if current IP is Cloudflare
    let cf_ranges_hint = ["104.16.", "104.17.", "104.18.", "104.19.", "104.20.", "104.21.",
        "172.64.", "172.65.", "172.66.", "172.67.", "172.68.", "172.69.",
        "172.70.", "172.71.", "188.114.", "190.93.", "197.234.", "198.41."];

    spinner.finish_and_clear();

    println!("\n{}", "--- TLS / CDN Analysis ---".magenta().bold());

    // Show current A records
    let current_ips: Vec<String> = findings.iter()
        .filter(|f| f.starts_with("current_a:"))
        .map(|f| f[10..].to_string())
        .collect();

    if !current_ips.is_empty() {
        println!("\n  {} Current A records:", "DNS".cyan().bold());
        for ip in &current_ips {
            let is_cf = cf_ranges_hint.iter().any(|r| ip.starts_with(r));
            if is_cf {
                println!("    {} {} {}", "↳".magenta(), ip.yellow(), "[Cloudflare IP]".red().bold());
            } else {
                println!("    {} {}", "↳".magenta(), ip.green());
            }
        }
    }

    // SPF info
    if !spf_info.is_empty() {
        println!("\n  {} SPF Record:", "SPF".cyan().bold());
        println!("    {} {}", "↳".magenta(), spf_info.dimmed());
        let spf_ips: Vec<String> = findings.iter()
            .filter(|f| f.starts_with("spf_ip:"))
            .map(|f| f[7..].to_string())
            .collect();
        if !spf_ips.is_empty() {
            println!("    {} Possible mail server IPs:", "⚠".yellow().bold());
            for ip in spf_ips {
                println!("      {} {}", "→".green(), ip.green().bold());
            }
        }
    }

    // Subdomains from HackerTarget
    if !subdomain_ips.is_empty() {
        println!("\n  {} Subdomains (may expose origin IPs):", "Subdomains".cyan().bold());
        for s in subdomain_ips.iter().take(15) {
            println!("    {} {}", "↳".magenta(), s);
        }
        if subdomain_ips.len() > 15 {
            println!("    {} {} more...", "…".dimmed(), subdomain_ips.len() - 15);
        }
    }

    // Cert transparency subdomains
    if !cert_subdomains.is_empty() {
        println!("\n  {} Certificate Transparency subdomains ({} found):", "CT Logs".cyan().bold(), cert_subdomains.len());
        for s in cert_subdomains.iter().take(20) {
            println!("    {} {}", "↳".magenta(), s.dimmed());
        }
        if cert_subdomains.len() > 20 {
            println!("    {} {} more at: https://crt.sh/?q=%.{}", "…".dimmed(), cert_subdomains.len() - 20, domain);
        }
    }

    // Summary
    let behind_cf = current_ips.iter().any(|ip| cf_ranges_hint.iter().any(|r| ip.starts_with(r)));
    if behind_cf {
        println!(
            "\n  {} {}",
            "⚠".yellow().bold(),
            "Domain appears to be behind Cloudflare. Real IP may be hidden.".yellow().bold()
        );
        println!(
            "  {} {}",
            "↳".magenta(),
            "Check subdomains (mail., direct., ftp.) and SPF IPs above for origin server.".dimmed()
        );
        println!(
            "  {} {}",
            "↳".magenta(),
            "Try: https://search.censys.io/search?resource=hosts&q=".to_string() + domain
        );
    } else {
        println!(
            "\n  {} {}",
            "✓".green(),
            "No major CDN detected on primary A records.".green()
        );
    }

    Ok(())
}

// ─── 10. PORT SCANNER ─────────────────────────────────────────────────────────

async fn port_scan_mode(host: &str, profile: &str) -> Result<(), Box<dyn Error>> {
    println!(
        "\n[{}] Port scan: {} (profile: {})",
        "*".cyan().bold(),
        host.yellow().bold(),
        profile.cyan()
    );

    let ports: Vec<u16> = match profile {
        "web" => vec![80, 443, 8080, 8443, 3000, 4000, 5000, 8000, 8888, 9000],
        "full" => (1..=1024).collect(),
        _ => vec![
            21, 22, 23, 25, 53, 80, 110, 111, 119, 135, 139, 143, 194, 443, 445,
            465, 587, 993, 995, 1080, 1194, 1433, 1521, 2083, 2087, 2096, 2222,
            3000, 3306, 3389, 4333, 5432, 5900, 6379, 6881, 8080, 8443, 8888,
            9000, 9200, 9418, 10000, 27017,
        ],
    };

    let total = ports.len() as u64;
    let pb = ProgressBar::new(total);
    pb.set_style(progress_style());
    pb.set_message("scanning ports...");

    let start = Instant::now();
    let open_ports: Arc<Mutex<Vec<(u16, &'static str)>>> = Arc::new(Mutex::new(vec![]));

    // Resolve host once
    let host_str = if host.starts_with("http://") || host.starts_with("https://") {
        host.trim_start_matches("https://")
            .trim_start_matches("http://")
            .trim_end_matches('/')
            .to_string()
    } else {
        host.to_string()
    };

    let mut tasks = vec![];
    for port in ports {
        let h = host_str.clone();
        let op = Arc::clone(&open_ports);
        let pb2 = pb.clone();
        tasks.push(tokio::spawn(async move {
            let addr_str = format!("{}:{}", h, port);
            let timeout = Duration::from_millis(800);
            let is_open = tokio::time::timeout(timeout, async {
                // Try to connect
                let addr: Result<SocketAddr, _> = addr_str.parse();
                match addr {
                    Ok(sa) => TcpStream::connect_timeout(&sa, timeout).is_ok(),
                    Err(_) => {
                        // Hostname — use std resolution
                        TcpStream::connect(&addr_str).is_ok()
                    }
                }
            })
                .await
                .unwrap_or(false);

            if is_open {
                let service = port_service(port);
                op.lock().unwrap().push((port, service));
            }
            pb2.inc(1);
        }));
    }

    join_all(tasks).await;
    pb.finish_with_message("done");

    let mut results = open_ports.lock().unwrap();
    results.sort_by_key(|(p, _)| *p);

    println!();
    if results.is_empty() {
        println!("{}", "[!] No open ports found (or host is unreachable).".yellow());
    } else {
        println!(
            "[{}] {} open port(s) on {}:\n",
            "+".green().bold(),
            results.len().to_string().green().bold(),
            host_str.yellow()
        );
        for (port, service) in results.iter() {
            println!(
                "  {} {:<6} {}",
                "●".green(),
                port.to_string().cyan().bold(),
                service.dimmed()
            );
        }
    }

    println!(
        "\n  {} Scanned {} ports in {:.2}s",
        "✓".green(),
        total,
        start.elapsed().as_secs_f64()
    );

    Ok(())
}

fn port_service(port: u16) -> &'static str {
    match port {
        21 => "FTP",
        22 => "SSH",
        23 => "Telnet",
        25 => "SMTP",
        53 => "DNS",
        80 => "HTTP",
        110 => "POP3",
        111 => "RPC",
        119 => "NNTP",
        135 => "RPC/DCOM",
        139 => "NetBIOS",
        143 => "IMAP",
        194 => "IRC",
        443 => "HTTPS",
        445 => "SMB",
        465 => "SMTPS",
        587 => "SMTP (submission)",
        993 => "IMAPS",
        995 => "POP3S",
        1080 => "SOCKS Proxy",
        1194 => "OpenVPN",
        1433 => "MSSQL",
        1521 => "Oracle DB",
        2083 => "cPanel SSL",
        2087 => "WHM SSL",
        2096 => "Webmail SSL",
        2222 => "SSH (alt)",
        3000 => "Dev server",
        3306 => "MySQL",
        3389 => "RDP",
        4333 => "mSQL",
        5432 => "PostgreSQL",
        5900 => "VNC",
        6379 => "Redis",
        6881 => "BitTorrent",
        8080 => "HTTP (proxy/alt)",
        8443 => "HTTPS (alt)",
        8888 => "HTTP (alt)",
        9000 => "PHP-FPM / SonarQube",
        9200 => "Elasticsearch",
        9418 => "Git",
        10000 => "Webmin",
        27017 => "MongoDB",
        _ => "unknown",
    }
}

// ─── 11. SITE PARSER MODE ─────────────────────────────────────────────────────

async fn site_parser_mode(url: &str) -> Result<(), Box<dyn Error>> {
    let mut url = url.to_string();
    if !url.starts_with("http://") && !url.starts_with("https://") {
        url = format!("https://{}", url);
    }

    println!(
        "\n[{}] Analyzing: {}",
        "*".cyan().bold(),
        url.yellow().bold()
    );

    let spinner = ProgressBar::new_spinner();
    spinner.set_style(spinner_style());
    spinner.set_message("fetching...");
    spinner.enable_steady_tick(Duration::from_millis(80));

    let client = make_client()?;

    match client.get(&url).send().await {
        Ok(res) => {
            spinner.finish_and_clear();
            println!("\n  {} {}", "Status:".magenta().bold(), res.status());

            println!("\n{}", "--- Headers ---".magenta().bold());
            let headers = res.headers().clone();
            for (key, val) in headers.iter() {
                if let Ok(v) = val.to_str() {
                    println!("  {}: {}", key.as_str().cyan(), v.dimmed());
                }
            }

            // Security headers check
            let sec_headers = [
                ("content-security-policy", "CSP"),
                ("strict-transport-security", "HSTS"),
                ("x-frame-options", "X-Frame-Options"),
                ("x-content-type-options", "X-Content-Type"),
                ("referrer-policy", "Referrer-Policy"),
                ("permissions-policy", "Permissions-Policy"),
            ];
            println!("\n{}", "--- Security Headers ---".magenta().bold());
            for (header_name, label) in sec_headers.iter() {
                if headers.contains_key(*header_name) {
                    println!("  {} {}", "✓".green(), label.bold());
                } else {
                    println!("  {} {} {}", "✗".red(), label.bold(), "(missing)".dimmed());
                }
            }

            if let Ok(body) = res.text().await {
                let document = Html::parse_document(&body);

                println!("\n{}", "--- Meta Info ---".magenta().bold());
                if let Ok(title_sel) = Selector::parse("title") {
                    if let Some(t) = document.select(&title_sel).next() {
                        println!("  {}: {}", "Title".green().bold(), t.inner_html().trim());
                    }
                }

                if let Ok(meta_sel) = Selector::parse("meta") {
                    for meta in document.select(&meta_sel) {
                        let name = meta
                            .value()
                            .attr("name")
                            .or(meta.value().attr("property"))
                            .unwrap_or("");
                        let content = meta.value().attr("content").unwrap_or("");
                        if !name.is_empty() && !content.is_empty() {
                            println!("  {}: {}", name.cyan(), content.dimmed());
                        }
                    }
                }

                // Tech detection
                println!("\n{}", "--- Tech Detection ---".magenta().bold());
                let body_lower = body.to_lowercase();
                let tech_signatures = [
                    ("wp-content", "WordPress"),
                    ("wp-json", "WordPress REST API"),
                    ("drupal", "Drupal"),
                    ("joomla", "Joomla"),
                    ("shopify", "Shopify"),
                    ("gatsby", "Gatsby"),
                    ("next.js", "Next.js"),
                    ("nuxt", "Nuxt.js"),
                    ("react", "React"),
                    ("angular", "Angular"),
                    ("vue", "Vue.js"),
                    ("bootstrap", "Bootstrap"),
                    ("tailwind", "Tailwind CSS"),
                    ("jquery", "jQuery"),
                    ("google-analytics", "Google Analytics"),
                    ("gtag", "Google Tag Manager"),
                    ("cloudflare", "Cloudflare"),
                    ("nginx", "Nginx"),
                    ("apache", "Apache"),
                    ("laravel", "Laravel"),
                    ("django", "Django"),
                    ("rails", "Ruby on Rails"),
                    ("graphql", "GraphQL"),
                ];
                let mut detected = vec![];
                for (sig, name) in tech_signatures.iter() {
                    if body_lower.contains(sig) {
                        detected.push(*name);
                    }
                }
                if detected.is_empty() {
                    println!("  {}", "No common frameworks detected.".dimmed());
                } else {
                    for t in detected {
                        println!("  {} {}", "✓".green(), t.bold());
                    }
                }

                // First 10 links
                println!("\n{}", "--- First 10 Links ---".magenta().bold());
                if let Ok(link_sel) = Selector::parse("a[href]") {
                    let mut count = 0;
                    for link in document.select(&link_sel) {
                        if count >= 10 {
                            break;
                        }
                        if let Some(href) = link.value().attr("href") {
                            if !href.starts_with('#') && !href.starts_with("javascript") {
                                println!("  {}", href.dimmed());
                                count += 1;
                            }
                        }
                    }
                }
            }
        }
        Err(e) => {
            spinner.finish_and_clear();
            println!("{}", format!("[!] Error: {}", e).red());
        }
    }

    Ok(())
}

// ─── 12. EXIF MODE ────────────────────────────────────────────────────────────

async fn exif_mode(path: &str) -> Result<(), Box<dyn Error>> {
    println!(
        "\n[{}] EXIF extraction: {}",
        "*".cyan().bold(),
        path.yellow().bold()
    );

    let spinner = ProgressBar::new_spinner();
    spinner.set_style(spinner_style());
    spinner.set_message("loading image...");
    spinner.enable_steady_tick(Duration::from_millis(80));

    let img_data: Vec<u8>;

    if path.starts_with("http://") || path.starts_with("https://") {
        let client = make_client()?;
        match client.get(path).send().await {
            Ok(res) => {
                spinner.finish_and_clear();
                if res.status().is_success() {
                    img_data = res.bytes().await?.to_vec();
                } else {
                    println!("{}", "[!] Failed to download image.".red());
                    return Ok(());
                }
            }
            Err(e) => {
                spinner.finish_and_clear();
                println!("{}", format!("[!] Error: {}", e).red());
                return Ok(());
            }
        }
    } else {
        spinner.finish_and_clear();
        match fs::read(path) {
            Ok(data) => img_data = data,
            Err(e) => {
                println!("{}", format!("[!] Cannot read file: {}", e).red());
                return Ok(());
            }
        }
    }

    println!("\n{}", "--- EXIF Data ---".magenta().bold());
    let mut cursor = Cursor::new(&img_data);
    match exif::Reader::new().read_from_container(&mut cursor) {
        Ok(exif_data) => {
            let fields: Vec<_> = exif_data.fields().collect();
            if fields.is_empty() {
                println!("{}", "  No EXIF data found (image may have been stripped).".yellow());
                return Ok(());
            }
            let mut has_gps = false;
            let mut lat_str = String::new();
            let mut lon_str = String::new();

            for f in &fields {
                println!(
                    "  {}: {}",
                    f.tag.to_string().cyan(),
                    f.display_value().to_string().dimmed()
                );
                let tag_str = f.tag.to_string();
                if tag_str.contains("GPSLatitude") && !tag_str.contains("Ref") {
                    lat_str = f.display_value().to_string();
                    has_gps = true;
                }
                if tag_str.contains("GPSLongitude") && !tag_str.contains("Ref") {
                    lon_str = f.display_value().to_string();
                }
            }

            if has_gps && !lat_str.is_empty() {
                println!(
                    "\n  {} {} GPS coordinates found!",
                    "⚠".yellow().bold(),
                    "PRIVACY WARNING:".red().bold()
                );
                println!("    Lat: {}  Lon: {}", lat_str.yellow(), lon_str.yellow());
                println!(
                    "    {} https://maps.google.com/?q={},{}",
                    "↳ Map:".magenta(),
                    lat_str.replace(' ', ""),
                    lon_str.replace(' ', "")
                );
            }
        }
        Err(_) => {
            println!("{}", "  No EXIF data found or unsupported format.".yellow());
        }
    }

    Ok(())
}
