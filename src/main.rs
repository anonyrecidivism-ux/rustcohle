use std::collections::{HashMap, HashSet};
use std::error::Error;
use std::fs;
use std::io::{self, Cursor, Write};
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use clap::{Parser, Subcommand};
use colored::*;
use futures::future::join_all;
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use reqwest::{header, Client, Proxy, StatusCode};
use scraper::{Html, Selector};
use serde::Deserialize;
use serde_json::Value;
use tokio::time::sleep;

// ═══════════════════════════════════════════════════════════════════════════════
// CONFIG
// ═══════════════════════════════════════════════════════════════════════════════

#[derive(Debug, Clone)]
struct Config {
    hibp_api_key: Option<String>,
    github_token: Option<String>,
    proxy: Option<String>,
    timeout_secs: u64,
    max_retries: u32,
}

impl Default for Config {
    fn default() -> Self {
        Config { hibp_api_key: None, github_token: None, proxy: None, timeout_secs: 12, max_retries: 3 }
    }
}

impl Config {
    fn load() -> Self {
        let mut cfg = Config::default();
        for path in config_paths() {
            if let Ok(text) = fs::read_to_string(&path) {
                for line in text.lines() {
                    let line = line.trim();
                    if line.is_empty() || line.starts_with('#') || line.starts_with('[') { continue; }
                    if let Some((k, v)) = line.split_once('=') {
                        let k = k.trim();
                        let v = v.trim().trim_matches('"').trim_matches('\'').to_string();
                        if v.is_empty() { continue; }
                        match k {
                            "hibp_api_key" => cfg.hibp_api_key = Some(v),
                            "github_token" => cfg.github_token = Some(v),
                            "proxy" => cfg.proxy = Some(v),
                            "timeout_secs" => { if let Ok(n) = v.parse() { cfg.timeout_secs = n; } }
                            "max_retries" => { if let Ok(n) = v.parse() { cfg.max_retries = n; } }
                            _ => {}
                        }
                    }
                }
                break;
            }
        }
        if let Ok(v) = std::env::var("HIBP_API_KEY") { if !v.is_empty() { cfg.hibp_api_key = Some(v); } }
        if let Ok(v) = std::env::var("GITHUB_TOKEN") { if !v.is_empty() { cfg.github_token = Some(v); } }
        if let Ok(v) = std::env::var("RUSTCOHLE_PROXY") { if !v.is_empty() { cfg.proxy = Some(v); } }
        cfg
    }

    fn build_client(&self) -> Result<Client, Box<dyn Error>> {
        let mut builder = Client::builder()
            .timeout(Duration::from_secs(self.timeout_secs))
            .connect_timeout(Duration::from_secs(8))
            .pool_idle_timeout(Duration::from_secs(30))
            .pool_max_idle_per_host(8)
            .user_agent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36")
            .redirect(reqwest::redirect::Policy::limited(5));
        if let Some(ref proxy_url) = self.proxy {
            match Proxy::all(proxy_url) {
                Ok(p) => { builder = builder.proxy(p); }
                Err(e) => { eprintln!("{} invalid proxy '{}': {}", "[!]".red(), proxy_url, e); }
            }
        }
        Ok(builder.build()?)
    }
}

fn config_paths() -> Vec<PathBuf> {
    let mut paths = vec![];
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() { paths.push(dir.join("config.toml")); }
    }
    paths.push(PathBuf::from("config.toml"));
    if let Ok(home) = std::env::var("HOME") {
        paths.push(PathBuf::from(home).join(".config/rustcohle/config.toml"));
    }
    paths
}

// ═══════════════════════════════════════════════════════════════════════════════
// CLI
// ═══════════════════════════════════════════════════════════════════════════════

#[derive(Parser)]
#[command(name = "rustcohle", about = "Rust Cohle — OSINT & Recon Framework", long_about = None, version)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
    /// Proxy URL (http/https/socks5), e.g. socks5://127.0.0.1:9050 for Tor
    #[arg(long, global = true)]
    proxy: Option<String>,
}

#[derive(Subcommand)]
enum Commands {
    /// Search username across 60+ social networks with correlation graph
    Username { username: String },
    /// Analyze website: headers, tech stack, security, links
    Site { url: String },
    /// GeoIP + ASN + threat flags for IP or domain
    Ip { target: String },
    /// Extract EXIF metadata from image (URL or local path)
    Exif { path: String },
    /// Check email across 20+ services (Holehe-style)
    Email { email: String },
    /// DNS lookup: A, AAAA, MX, TXT, NS, CNAME, SOA, CAA records
    Dns { domain: String },
    /// RDAP/Whois lookup for domain
    Whois { domain: String },
    /// Phone number lookup, carrier detection, country prefix
    Phone { number: String },
    /// Wayback Machine: find archived snapshots
    Wayback { url: String },
    /// HaveIBeenPwned: check email for data breaches
    Hibp { email: String },
    /// TLS/CDN fingerprint: detect real IP behind Cloudflare/CDN
    Tls { domain: String },
    /// Port scanner: scan common/web/full ports on host
    Ports {
        host: String,
        #[arg(short, long, default_value = "common", help = "Profile: common|full|web|top1000")]
        profile: String,
    },
    /// GitHub deep recon: repos, emails from commits, gists, orgs, keys
    Git { username: String },
    /// Subdomain enumeration + takeover detection
    Crt { domain: String },
    /// HTTP header fingerprint + WAF/CDN detection + security score
    Headers { url: String },
    /// Paste search: find mentions on Pastebin & similar
    Paste { query: String },
    /// Banner grab on open ports
    Banner { host: String },
    /// Reverse IP: find other domains hosted on the same IP
    ReverseIp { target: String },
    /// ASN lookup: announced prefixes, peers, org info
    Asn { target: String },
    /// Extract metadata from documents (PDF, DOCX, images)
    Meta { path: String },
    /// Full recon chain: ip + dns + whois + crt + tls + headers + ports
    Recon { target: String },
    /// Generate username variations + quick presence check
    Permute { username: String },
    /// Generate Google/Bing dork links for a target domain
    Dorks { target: String },
    /// Hash a site's favicon for Shodan/FOFA pivoting (CDN bypass)
    Favicon { target: String },
}

// ═══════════════════════════════════════════════════════════════════════════════
// DATA STRUCTURES
// ═══════════════════════════════════════════════════════════════════════════════

#[derive(Debug, Deserialize, Clone)]
struct Site {
    url: String,
    #[serde(rename = "errorType")]
    error_type: String,
    #[serde(rename = "errorMsg")]
    error_msg: Option<String>,
    #[serde(default)]
    category: Option<String>,
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
    category: String,
}

#[derive(Debug)]
struct Summary {
    found: usize,
    not_found: usize,
    errors: usize,
    duration: Duration,
}

// ═══════════════════════════════════════════════════════════════════════════════
// HELPERS
// ═══════════════════════════════════════════════════════════════════════════════

fn get_data_dir() -> PathBuf {
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            if dir.join("sites.json").exists() { return dir.to_path_buf(); }
        }
    }
    PathBuf::from(".")
}

fn print_banner() {
    // cat mascot on the left (magenta), wordmark on the right (cyan)
    let cat = [
        r"  ╱|、   ",
        r" (˚ˎ 。7 ",
        r"  |、˜〵 ",
        r"  じしˍ,)ノ",
    ];
    let word = [
        r"┬─┐┬ ┬┌─┐┌┬┐  ┌─┐┌─┐┬ ┬┬  ┌─┐",
        r"├┬┘│ │└─┐ │   │  │ │├─┤│  ├┤ ",
        r"┴└─└─┘└─┘ ┴   └─┘└─┘┴ ┴┴─┘└─┘",
        r"",
    ];
    println!();
    for i in 0..cat.len() {
        println!("  {}   {}", cat[i].magenta().bold(), word[i].cyan().bold());
    }
    println!("{}", "  osint & recon framework  ·  v3.1".cyan());
    println!("{}", "  github.com/anonyrecidivism-ux/rustcohle".dimmed());
    println!("{}", "  \"time is a flat circle.\"".dimmed());
    println!();
}

fn section(title: &str) {
    println!("\n{} {}", "▶".magenta().bold(), title.bold());
    println!("{}", "─".repeat(54).dimmed());
}

fn print_summary(label: &str, s: &Summary) {
    println!();
    println!("{}", "━".repeat(54).dimmed());
    println!("  {} {}", "summary:".bold(), label.cyan().bold());
    println!(
        "  {} {}   {} {}   {} {}   {} {:.2}s",
        "✓".green().bold(), s.found.to_string().green().bold(),
        "✗".red(),          s.not_found.to_string().red(),
        "!".yellow(),       s.errors.to_string().yellow(),
        "⏱".dimmed(),       s.duration.as_secs_f64()
    );
    println!("{}", "━".repeat(54).dimmed());
}

fn bar_style() -> ProgressStyle {
    ProgressStyle::with_template("{spinner:.magenta} [{bar:40.cyan/blue}] {pos}/{len} {msg}")
        .unwrap().progress_chars("█▓░")
}

fn spin_style() -> ProgressStyle {
    ProgressStyle::with_template("{spinner:.cyan} {msg}")
        .unwrap().tick_strings(&["⠋","⠙","⠹","⠸","⠼","⠴","⠦","⠧","⠇","⠏","✓"])
}

fn spinner(msg: &str) -> ProgressBar {
    let pb = ProgressBar::new_spinner();
    pb.set_style(spin_style());
    pb.set_message(msg.to_string());
    pb.enable_steady_tick(Duration::from_millis(80));
    pb
}

fn row(key: &str, val: &str) {
    println!("  {:<22} {}", format!("{}:", key).cyan(), val);
}

fn strip_proto(s: &str) -> String {
    s.trim_start_matches("https://").trim_start_matches("http://").trim_end_matches('/').to_string()
}

// Resolve a domain to its first A record IP via DoH. Used by reverse-ip / asn / tls.
// GET with exponential backoff on 429 / 5xx / transport errors.
// Honors the Retry-After header when the server sends one.
// Used by the rate-limit-prone endpoints (crt.sh, HIBP, ipapi, RIPEstat).
async fn get_with_retry(client: &Client, url: &str, max_retries: u32) -> Option<reqwest::Response> {
    let mut attempt: u32 = 0;
    loop {
        match client.get(url).send().await {
            Ok(resp) => {
                let status = resp.status();
                let retryable = status.as_u16() == 429 || status.is_server_error();
                if retryable && attempt < max_retries {
                    // prefer the server's Retry-After (seconds); else exponential 1,2,4,8...
                    let wait = resp
                        .headers()
                        .get(reqwest::header::RETRY_AFTER)
                        .and_then(|v| v.to_str().ok())
                        .and_then(|s| s.trim().parse::<u64>().ok())
                        .unwrap_or_else(|| 1u64 << attempt);
                    let wait = wait.min(30); // never sleep more than 30s
                    sleep(Duration::from_secs(wait)).await;
                    attempt += 1;
                    continue;
                }
                return Some(resp);
            }
            Err(_) => {
                if attempt < max_retries {
                    let wait = (1u64 << attempt).min(30);
                    sleep(Duration::from_secs(wait)).await;
                    attempt += 1;
                    continue;
                }
                return None;
            }
        }
    }
}

async fn resolve_ip(client: &Client, host: &str) -> Option<String> {
    if host.parse::<IpAddr>().is_ok() { return Some(host.to_string()); }
    let url = format!("https://dns.google/resolve?name={}&type=A", host);
    if let Ok(res) = client.get(&url).send().await {
        if let Ok(j) = res.json::<Value>().await {
            if let Some(answers) = j.get("Answer").and_then(|v| v.as_array()) {
                for ans in answers {
                    if ans["type"].as_u64() == Some(1) {
                        if let Some(ip) = ans["data"].as_str() { return Some(ip.to_string()); }
                    }
                }
            }
        }
    }
    None
}

// ═══════════════════════════════════════════════════════════════════════════════
// INTERACTIVE MENU
// ═══════════════════════════════════════════════════════════════════════════════

async fn interactive_menu(cfg: &Config) -> Result<(), Box<dyn Error>> {
    loop {
        println!("\n{}", "  select a module:".bold());
        let items = [
            ("1",  "username <name>",   "search 60+ social networks + graph"),
            ("2",  "email <addr>",      "check email across 20+ services"),
            ("3",  "hibp <addr>",       "HaveIBeenPwned breach check"),
            ("4",  "ip <ip|domain>",    "GeoIP + ASN + threat flags"),
            ("5",  "dns <domain>",      "DNS records"),
            ("6",  "whois <domain>",    "RDAP/Whois lookup"),
            ("7",  "phone <number>",    "phone number lookup"),
            ("8",  "wayback <url>",     "Wayback Machine snapshots"),
            ("9",  "tls <domain>",      "TLS/CDN fingerprint + real IP"),
            ("10", "ports <host>",      "port scanner"),
            ("11", "site <url>",        "site analyzer + tech detection"),
            ("12", "exif <path|url>",   "EXIF metadata extractor"),
            ("13", "git <username>",    "GitHub deep recon"),
            ("14", "crt <domain>",      "subdomains + takeover detection"),
            ("15", "headers <url>",     "HTTP headers + WAF detection"),
            ("16", "paste <query>",     "paste sites search"),
            ("17", "banner <host>",     "banner grab"),
            ("18", "reverseip <target>","domains on same IP"),
            ("19", "asn <as|ip>",       "ASN prefixes + org info"),
            ("20", "meta <path|url>",   "document metadata (pdf/docx)"),
            ("21", "recon <target>",    "full recon chain"),
            ("22", "permute <name>",    "username variations + check"),
            ("23", "dorks <domain>",    "google/bing dork links"),
            ("24", "favicon <url>",     "favicon hash for shodan/fofa"),
        ];
        for (n, cmd, desc) in &items {
            println!("  {}  {:<24} {}", format!("{}.", n).yellow(), cmd.bold(), desc.dimmed());
        }
        println!("  {}  exit", "0.".yellow());
        print!("\n> ");
        io::stdout().flush()?;

        let mut choice = String::new();
        io::stdin().read_line(&mut choice)?;
        let parts: Vec<&str> = choice.trim().splitn(2, ' ').collect();
        let cmd = match parts[0] {
            "0" | "exit" => { println!("{}", "time is a flat circle. goodbye.".green()); break; }
            "1"|"username"  => "username",
            "2"|"email"     => "email",
            "3"|"hibp"      => "hibp",
            "4"|"ip"        => "ip",
            "5"|"dns"       => "dns",
            "6"|"whois"     => "whois",
            "7"|"phone"     => "phone",
            "8"|"wayback"   => "wayback",
            "9"|"tls"       => "tls",
            "10"|"ports"    => "ports",
            "11"|"site"     => "site",
            "12"|"exif"     => "exif",
            "13"|"git"      => "git",
            "14"|"crt"      => "crt",
            "15"|"headers"  => "headers",
            "16"|"paste"    => "paste",
            "17"|"banner"   => "banner",
            "18"|"reverseip"=> "reverseip",
            "19"|"asn"      => "asn",
            "20"|"meta"     => "meta",
            "21"|"recon"    => "recon",
            "22"|"permute"  => "permute",
            "23"|"dorks"    => "dorks",
            "24"|"favicon"  => "favicon",
            _ => { println!("{}", "[!] unknown command".red()); continue; }
        };
        let arg = if parts.len() > 1 {
            parts[1].to_string()
        } else {
            print!("  enter value: ");
            io::stdout().flush()?;
            let mut v = String::new();
            io::stdin().read_line(&mut v)?;
            v.trim().to_string()
        };
        if arg.is_empty() { continue; }
        dispatch(cfg, cmd, &arg).await?;
    }
    Ok(())
}

async fn dispatch(cfg: &Config, cmd: &str, arg: &str) -> Result<(), Box<dyn Error>> {
    match cmd {
        "username"  => sherlock_mode(cfg, arg).await?,
        "email"     => email_mode(cfg, arg).await?,
        "hibp"      => hibp_mode(cfg, arg).await?,
        "ip"        => ip_lookup_mode(cfg, arg).await?,
        "dns"       => dns_mode(cfg, arg).await?,
        "whois"     => whois_mode(cfg, arg).await?,
        "phone"     => phone_mode(cfg, arg).await?,
        "wayback"   => wayback_mode(cfg, arg).await?,
        "tls"       => tls_mode(cfg, arg).await?,
        "ports"     => port_scan_mode(arg, "common").await?,
        "site"      => site_mode(cfg, arg).await?,
        "exif"      => exif_mode(cfg, arg).await?,
        "git"       => git_mode(cfg, arg).await?,
        "crt"       => crt_mode(cfg, arg).await?,
        "headers"   => headers_mode(cfg, arg).await?,
        "paste"     => paste_mode(cfg, arg).await?,
        "banner"    => banner_mode(cfg, arg).await?,
        "reverseip" => reverse_ip_mode(cfg, arg).await?,
        "asn"       => asn_mode(cfg, arg).await?,
        "meta"      => meta_mode(cfg, arg).await?,
        "recon"     => recon_mode(cfg, arg).await?,
        "permute"   => permute_mode(cfg, arg).await?,
        "dorks"     => dorks_mode(cfg, arg).await?,
        "favicon"   => favicon_mode(cfg, arg).await?,
        _ => {}
    }
    Ok(())
}

// ═══════════════════════════════════════════════════════════════════════════════
// MAIN
// ═══════════════════════════════════════════════════════════════════════════════

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    print_banner();
    let cli = Cli::parse();

    let mut cfg = Config::load();
    if let Some(ref p) = cli.proxy { cfg.proxy = Some(p.clone()); }
    if cfg.proxy.is_some() {
        println!("  {} routing through proxy: {}", "⚡".yellow(), cfg.proxy.as_deref().unwrap_or("").dimmed());
    }

    match cli.command {
        Some(Commands::Username { username })   => sherlock_mode(&cfg, &username).await?,
        Some(Commands::Site { url })            => site_mode(&cfg, &url).await?,
        Some(Commands::Ip { target })           => ip_lookup_mode(&cfg, &target).await?,
        Some(Commands::Exif { path })           => exif_mode(&cfg, &path).await?,
        Some(Commands::Email { email })         => email_mode(&cfg, &email).await?,
        Some(Commands::Dns { domain })          => dns_mode(&cfg, &domain).await?,
        Some(Commands::Whois { domain })        => whois_mode(&cfg, &domain).await?,
        Some(Commands::Phone { number })        => phone_mode(&cfg, &number).await?,
        Some(Commands::Wayback { url })         => wayback_mode(&cfg, &url).await?,
        Some(Commands::Hibp { email })          => hibp_mode(&cfg, &email).await?,
        Some(Commands::Tls { domain })          => tls_mode(&cfg, &domain).await?,
        Some(Commands::Ports { host, profile }) => port_scan_mode(&host, &profile).await?,
        Some(Commands::Git { username })        => git_mode(&cfg, &username).await?,
        Some(Commands::Crt { domain })          => crt_mode(&cfg, &domain).await?,
        Some(Commands::Headers { url })         => headers_mode(&cfg, &url).await?,
        Some(Commands::Paste { query })         => paste_mode(&cfg, &query).await?,
        Some(Commands::Banner { host })         => banner_mode(&cfg, &host).await?,
        Some(Commands::ReverseIp { target })    => reverse_ip_mode(&cfg, &target).await?,
        Some(Commands::Asn { target })          => asn_mode(&cfg, &target).await?,
        Some(Commands::Meta { path })           => meta_mode(&cfg, &path).await?,
        Some(Commands::Recon { target })        => recon_mode(&cfg, &target).await?,
        Some(Commands::Permute { username })    => permute_mode(&cfg, &username).await?,
        Some(Commands::Dorks { target })        => dorks_mode(&cfg, &target).await?,
        Some(Commands::Favicon { target })      => favicon_mode(&cfg, &target).await?,
        None => interactive_menu(&cfg).await?,
    }
    Ok(())
}

// ═══════════════════════════════════════════════════════════════════════════════
// MODULE: SHERLOCK — username search with category grouping
// ═══════════════════════════════════════════════════════════════════════════════

async fn sherlock_mode(cfg: &Config, username: &str) -> Result<(), Box<dyn Error>> {
    section(&format!("username search: {}", username.yellow().bold()));

    let data_dir = get_data_dir();
    let raw = fs::read_to_string(data_dir.join("sites.json"))
        .map_err(|_| "sites.json not found — place it next to the binary")?;
    let sites: Sites = serde_json::from_str(&raw)?;

    let client = cfg.build_client()?;
    let total = sites.len() as u64;
    let mp = MultiProgress::new();
    let pb = mp.add(ProgressBar::new(total));
    pb.set_style(bar_style());
    pb.set_message("scanning...");

    let results: Arc<Mutex<Vec<ScanResult>>> = Arc::new(Mutex::new(vec![]));
    let start = Instant::now();

    let mut tasks = vec![];
    for (name, site) in sites {
        let c = client.clone();
        let u = username.to_string();
        let r = Arc::clone(&results);
        let pb2 = pb.clone();
        tasks.push(tokio::spawn(async move {
            let res = check_site(&c, &name, &site, &u).await;
            r.lock().unwrap().push(res);
            pb2.inc(1);
        }));
    }
    join_all(tasks).await;
    pb.finish_with_message("done");

    let mut locked = results.lock().unwrap();
    locked.sort_by(|a, b| b.found.cmp(&a.found).then(a.name.cmp(&b.name)));

    let found: Vec<&ScanResult> = locked.iter().filter(|r| r.found).collect();
    let not_found_n = locked.len() - found.len();

    // Group found accounts by category — this is the "correlation graph"
    if !found.is_empty() {
        let mut by_cat: HashMap<String, Vec<&ScanResult>> = HashMap::new();
        for r in &found {
            by_cat.entry(r.category.clone()).or_default().push(*r);
        }
        let mut cats: Vec<&String> = by_cat.keys().collect();
        cats.sort();

        println!("\n  {} {} accounts found across {} categories:",
                 "⊕".green().bold(), found.len().to_string().green().bold(), cats.len());

        for cat in cats {
            let entries = &by_cat[cat];
            println!("\n  {} {}", "┌─".magenta(), cat.to_uppercase().magenta().bold());
            for (i, r) in entries.iter().enumerate() {
                let branch = if i == entries.len() - 1 { "└─" } else { "├─" };
                println!("  {} {:<18} {}", branch.magenta(), r.name.bold(), r.url.cyan());
                if let Some(ref e) = r.extra {
                    let pad = if i == entries.len() - 1 { "   " } else { "│  " };
                    println!("  {}  {} {}", pad.magenta(), "↳".dimmed(), e.dimmed());
                }
            }
        }
    } else {
        println!("\n  {} no accounts found.", "✗".red());
    }

    print_summary(username, &Summary { found: found.len(), not_found: not_found_n, errors: 0, duration: start.elapsed() });
    Ok(())
}

async fn check_site(client: &Client, name: &str, site: &Site, username: &str) -> ScanResult {
    let url = site.url.replace("{}", username);
    let category = site.category.clone().unwrap_or_else(|| "other".to_string());
    let mut found = false;
    let mut extra: Option<String> = None;
    let mut page_body = String::new();

    if let Ok(resp) = client.get(&url).send().await {
        let status = resp.status();
        if let Ok(body) = resp.text().await {
            page_body = body;
            match site.error_type.as_str() {
                "status_code" => { found = status == StatusCode::OK; }
                "title" => {
                    if let Some(ref msg) = site.error_msg {
                        let doc = Html::parse_document(&page_body);
                        if let Ok(sel) = Selector::parse("title") {
                            if let Some(t) = doc.select(&sel).next() {
                                found = !t.inner_html().contains(msg.as_str());
                            }
                        }
                    }
                }
                _ => {}
            }
        }
    }

    if found {
        if name == "GitHub" {
            let api = format!("https://api.github.com/users/{}", username);
            if let Ok(r) = client.get(&api).header("Accept","application/vnd.github+json").send().await {
                if let Ok(j) = r.json::<Value>().await {
                    let mut parts = vec![];
                    for (k, label) in [("name","name"),("bio","bio"),("location","location"),("company","company")] {
                        if let Some(v) = j.get(k).and_then(|v| v.as_str()) {
                            if !v.is_empty() { parts.push(format!("{}: {}", label, v)); }
                        }
                    }
                    if let Some(v) = j.get("public_repos").and_then(|v| v.as_u64()) { parts.push(format!("repos: {}", v)); }
                    if let Some(v) = j.get("followers").and_then(|v| v.as_u64()) { parts.push(format!("followers: {}", v)); }
                    if !parts.is_empty() { extra = Some(parts.join("  |  ")); }
                }
            }
        } else {
            let doc = Html::parse_document(&page_body);
            if let Ok(sel) = Selector::parse(r#"meta[name="description"],meta[property="og:description"]"#) {
                if let Some(el) = doc.select(&sel).next() {
                    if let Some(c) = el.value().attr("content") {
                        let s = c.trim().replace('\n', " ");
                        if !s.is_empty() {
                            extra = Some(if s.chars().count() > 80 {
                                format!("{}…", s.chars().take(77).collect::<String>())
                            } else { s });
                        }
                    }
                }
            }
        }
    }

    ScanResult { found, name: name.to_string(), url, extra, category }
}

// ═══════════════════════════════════════════════════════════════════════════════
// MODULE: EMAIL CHECK
// ═══════════════════════════════════════════════════════════════════════════════

async fn email_mode(cfg: &Config, email: &str) -> Result<(), Box<dyn Error>> {
    section(&format!("email check: {}", email.yellow().bold()));

    let data_dir = get_data_dir();
    let raw = fs::read_to_string(data_dir.join("emails.json")).map_err(|_| "emails.json not found")?;
    let checks: Vec<EmailCheck> = serde_json::from_str(&raw)?;

    let client = cfg.build_client()?;
    let pb = ProgressBar::new(checks.len() as u64);
    pb.set_style(bar_style());
    let start = Instant::now();
    let results: Arc<Mutex<Vec<(bool, String)>>> = Arc::new(Mutex::new(vec![]));

    let mut tasks = vec![];
    for check in checks {
        let c = client.clone();
        let e = email.to_string();
        let r = Arc::clone(&results);
        let pb2 = pb.clone();
        tasks.push(tokio::spawn(async move {
            let res = check_email_on_site(&c, &e, check).await;
            r.lock().unwrap().push(res);
            pb2.inc(1);
        }));
    }
    join_all(tasks).await;
    pb.finish_with_message("done");

    let mut found = 0usize;
    let mut not_found = 0usize;
    println!();
    let mut locked = results.lock().unwrap();
    locked.sort_by(|a, b| b.0.cmp(&a.0).then(a.1.cmp(&b.1)));
    for (f, name) in locked.iter() {
        if *f { found += 1; println!("  [{}] {}", "+".green().bold(), name.bold()); }
        else  { not_found += 1; println!("  [{}] {:<24} {}", "-".red(), name.bold(), "not registered".dimmed()); }
    }
    print_summary(email, &Summary { found, not_found, errors: 0, duration: start.elapsed() });
    Ok(())
}

async fn check_email_on_site(client: &Client, email: &str, check: EmailCheck) -> (bool, String) {
    let md5_email = format!("{:x}", md5::compute(email.to_lowercase().as_bytes()));
    let url = check.url.replace("{email}", email).replace("{md5_email}", &md5_email);
    let mut rb = match check.method.as_str() { "POST" => client.post(&url), _ => client.get(&url) };
    if let Some(hdrs) = check.headers {
        let mut hmap = header::HeaderMap::new();
        for (k, v) in hdrs {
            if let (Ok(hn), Ok(hv)) = (header::HeaderName::from_bytes(k.as_bytes()), header::HeaderValue::from_str(&v)) {
                hmap.insert(hn, hv);
            }
        }
        rb = rb.headers(hmap);
    }
    if let Some(body) = check.body { rb = rb.body(body.replace("{email}", email)); }
    let found = match rb.send().await {
        Ok(resp) => match check.check_type.as_str() {
            "status" => resp.status().is_success(),
            "json_key" => {
                if let (Ok(j), Some(k), Some(exp)) = (resp.json::<Value>().await, check.json_key, check.expected_value) {
                    j.get(k).map(|v| v == &exp).unwrap_or(false)
                } else { false }
            }
            _ => false,
        },
        Err(_) => false,
    };
    (found, check.name)
}

// ═══════════════════════════════════════════════════════════════════════════════
// MODULE: HIBP
// ═══════════════════════════════════════════════════════════════════════════════

async fn hibp_mode(cfg: &Config, email: &str) -> Result<(), Box<dyn Error>> {
    section(&format!("haveibeenpwned: {}", email.yellow().bold()));

    let api_key = cfg.hibp_api_key.clone().unwrap_or_default();
    if api_key.is_empty() {
        println!("  {} {}", "⚠".yellow(), "no API key set — full results need a key:".yellow());
        println!("    {}", "set hibp_api_key in config.toml or HIBP_API_KEY env".dimmed());
        println!("    {}", "https://haveibeenpwned.com/API/Key".dimmed());
        println!();
    }

    let sp = spinner("querying HIBP...");
    let client = cfg.build_client()?;
    let url = format!("https://haveibeenpwned.com/api/v3/breachedaccount/{}?truncateResponse=false", urlencoding::encode(email));
    // HIBP retry loop — keeps the custom hibp-api-key header on each attempt
    let mut attempt: u32 = 0;
    let res = loop {
        let mut req = client.get(&url).header("User-Agent", "RustCohle-OSINT");
        if !api_key.is_empty() { req = req.header("hibp-api-key", &api_key); }
        match req.send().await {
            Ok(r) => {
                if r.status().as_u16() == 429 && attempt < cfg.max_retries {
                    let wait = r.headers()
                        .get(reqwest::header::RETRY_AFTER)
                        .and_then(|v| v.to_str().ok())
                        .and_then(|s| s.trim().parse::<u64>().ok())
                        .unwrap_or_else(|| 1u64 << attempt)
                        .min(30);
                    sp.set_message(format!("rate limited, retrying in {}s...", wait));
                    sleep(Duration::from_secs(wait)).await;
                    attempt += 1;
                    continue;
                }
                break Ok(r);
            }
            Err(e) => break Err(e),
        }
    };
    sp.finish_and_clear();

    match res {
        Ok(r) => match r.status().as_u16() {
            200 => {
                if let Ok(breaches) = r.json::<Vec<Value>>().await {
                    println!("\n  [{}] found in {} breach(es):\n", "!".red().bold(), breaches.len().to_string().red().bold());
                    for b in &breaches {
                        let name   = b["Name"].as_str().unwrap_or("?");
                        let domain = b["Domain"].as_str().unwrap_or("");
                        let date   = b["BreachDate"].as_str().unwrap_or("?");
                        let count  = b["PwnCount"].as_u64().unwrap_or(0);
                        let data   = b["DataClasses"].as_array()
                            .map(|a| a.iter().filter_map(|v| v.as_str()).collect::<Vec<_>>().join(", "))
                            .unwrap_or_default();
                        println!("  {} {} {}", "■".red(), name.bold(), format!("({})", domain).dimmed());
                        row("date", date);
                        row("records", &count.to_string());
                        row("data", &data);
                        println!();
                    }
                }
            }
            404 => println!("\n  [{}] {}", "✓".green().bold(), "no breaches found for this email.".green()),
            401 => println!("\n  [{}] api key required or invalid", "!".yellow()),
            429 => println!("  [!] rate limited by HIBP. try again in a moment."),
            s   => println!("  [!] HIBP returned status: {}", s),
        },
        Err(e) => println!("  [!] error: {}", e),
    }
    Ok(())
}

// ═══════════════════════════════════════════════════════════════════════════════
// MODULE: IP LOOKUP
// ═══════════════════════════════════════════════════════════════════════════════

async fn ip_lookup_mode(cfg: &Config, target: &str) -> Result<(), Box<dyn Error>> {
    section(&format!("ip/geo lookup: {}", target.yellow().bold()));
    let sp = spinner("querying...");
    let client = cfg.build_client()?;

    // Primary source: ip-api.com — free, generous limit (45 req/min), no key.
    // Returns status:"success"|"fail" in the body, so we check that explicitly.
    let url = format!(
        "http://ip-api.com/json/{}?fields=status,message,query,reverse,city,regionName,country,countryCode,zip,lat,lon,timezone,isp,org,as,asname,proxy,hosting,mobile",
        target
    );

    let mut printed_geo = false;
    if let Some(res) = get_with_retry(&client, &url, cfg.max_retries).await {
        let status = res.status();
        match res.json::<Value>().await {
            Ok(j) => {
                sp.finish_and_clear();
                let api_status = j.get("status").and_then(|v| v.as_str()).unwrap_or("");
                if api_status == "fail" {
                    let msg = j.get("message").and_then(|v| v.as_str()).unwrap_or("unknown error");
                    println!("  {} ip-api could not resolve '{}': {}", "[!]".red(), target, msg.yellow());
                } else {
                    section("geo / asn");
                    let fields = [
                        ("query","IP Address"),("reverse","Reverse DNS"),("city","City"),
                        ("regionName","Region"),("country","Country"),("countryCode","Country Code"),
                        ("zip","Postal"),("lat","Latitude"),("lon","Longitude"),
                        ("timezone","Timezone"),("isp","ISP"),("org","Organization"),
                        ("as","ASN"),("asname","AS Name"),
                    ];
                    for (key, label) in &fields {
                        if let Some(v) = j.get(*key) {
                            let s = if v.is_string() { v.as_str().unwrap_or("").to_string() } else { v.to_string() };
                            if !s.is_empty() && s != "null" { row(label, &s); }
                        }
                    }
                    printed_geo = true;

                    section("threat flags");
                    for (flag, label) in [("proxy","proxy/vpn"),("hosting","hosting/datacenter"),("mobile","mobile network")] {
                        if let Some(v) = j.get(flag).and_then(|v| v.as_bool()) {
                            let icon = if v { "⚠".yellow().to_string() } else { "✓".green().to_string() };
                            println!("  {}  {}", icon, label);
                        }
                    }

                    // hint if it looks like a CDN/host rather than an origin
                    let hosting = ["cloudflare","amazon","google","digitalocean","linode","vultr","ovh","hetzner","contabo","akamai","fastly"];
                    let org_blob = format!("{} {}",
                                           j.get("org").and_then(|v| v.as_str()).unwrap_or(""),
                                           j.get("isp").and_then(|v| v.as_str()).unwrap_or("")
                    ).to_lowercase();
                    let is_host = j.get("hosting").and_then(|v| v.as_bool()).unwrap_or(false)
                        || hosting.iter().any(|h| org_blob.contains(h));
                    if is_host {
                        println!("\n  {} {}", "⚠".yellow().bold(), "hosting/CDN — may not be the real origin IP".yellow());
                        println!("    {} try: tls <domain>  or  favicon <url>", "↳".magenta());
                    }
                }
            }
            Err(e) => {
                sp.finish_and_clear();
                println!("  {} ip-api returned status {} but the body wasn't valid JSON: {}",
                         "[!]".red(), status.as_u16(), e);
            }
        }
    } else {
        sp.finish_and_clear();
        println!("  {} request to ip-api.com failed (network/proxy/rate-limit after retries)", "[!]".red());
        println!("    {} check connectivity, or your --proxy setting", "↳".dimmed());
        return Ok(());
    }

    // Optional second opinion from ipapi.co (currency, languages) — best-effort, never fatal.
    if printed_geo {
        let url2 = format!("https://ipapi.co/{}/json/", target);
        if let Some(r2) = get_with_retry(&client, &url2, 1).await {
            if let Ok(j2) = r2.json::<Value>().await {
                if !j2.get("error").and_then(|v| v.as_bool()).unwrap_or(false) {
                    let mut extras = vec![];
                    for (key, label) in [("currency","Currency"),("languages","Languages"),("org","ISP Org")] {
                        if let Some(v) = j2.get(key).and_then(|v| v.as_str()) {
                            if !v.is_empty() { extras.push((label, v.to_string())); }
                        }
                    }
                    if !extras.is_empty() {
                        section("extra (ipapi.co)");
                        for (label, v) in extras { row(label, &v); }
                    }
                }
            }
        }
    }
    Ok(())
}

// ═══════════════════════════════════════════════════════════════════════════════
// MODULE: DNS
// ═══════════════════════════════════════════════════════════════════════════════

async fn dns_mode(cfg: &Config, domain: &str) -> Result<(), Box<dyn Error>> {
    section(&format!("dns records: {}", domain.yellow().bold()));
    let client = cfg.build_client()?;
    let record_types = ["A","AAAA","MX","NS","TXT","CNAME","SOA","CAA"];
    let start = Instant::now();
    let pb = ProgressBar::new(record_types.len() as u64);
    pb.set_style(bar_style());
    let mut found_any = false;

    for rtype in &record_types {
        let url = format!("https://dns.google/resolve?name={}&type={}", domain, rtype);
        sleep(Duration::from_millis(60)).await;
        if let Ok(res) = client.get(&url).send().await {
            if let Ok(j) = res.json::<Value>().await {
                if let Some(answers) = j.get("Answer").and_then(|a| a.as_array()) {
                    if !answers.is_empty() {
                        pb.suspend(|| {
                            println!("\n  {} records:", rtype.cyan().bold());
                            for ans in answers {
                                let data = ans["data"].as_str().unwrap_or("?");
                                let ttl  = ans["TTL"].as_u64().unwrap_or(0);
                                println!("    {} {}  {}", "↳".magenta(), data, format!("ttl {}", ttl).dimmed());
                            }
                        });
                        found_any = true;
                    }
                }
            }
        }
        pb.inc(1);
    }
    pb.finish_and_clear();
    if !found_any { println!("  [!] no DNS records found."); }
    println!("\n  {} done in {:.2}s", "✓".green(), start.elapsed().as_secs_f64());
    Ok(())
}

// ═══════════════════════════════════════════════════════════════════════════════
// MODULE: WHOIS / RDAP
// ═══════════════════════════════════════════════════════════════════════════════

async fn whois_mode(cfg: &Config, domain: &str) -> Result<(), Box<dyn Error>> {
    section(&format!("whois/rdap: {}", domain.yellow().bold()));
    let sp = spinner("querying rdap...");
    let client = cfg.build_client()?;
    let url = format!("https://rdap.org/domain/{}", domain);

    match client.get(&url).send().await {
        Ok(res) => {
            sp.finish_and_clear();
            if res.status().is_success() {
                if let Ok(j) = res.json::<Value>().await {
                    if let Some(v) = j.get("ldhName").and_then(|v| v.as_str()) { row("Domain", v); }
                    if let Some(arr) = j.get("status").and_then(|v| v.as_array()) {
                        let s: Vec<&str> = arr.iter().filter_map(|v| v.as_str()).collect();
                        row("Status", &s.join(", "));
                    }
                    if let Some(evs) = j.get("events").and_then(|v| v.as_array()) {
                        for ev in evs {
                            let action = ev["eventAction"].as_str().unwrap_or("");
                            let date   = ev["eventDate"].as_str().unwrap_or("?");
                            match action {
                                "registration" => row("Registered", date),
                                "last changed" => row("Updated", date),
                                "expiration"   => row("Expires", &date.yellow().to_string()),
                                _ => {}
                            }
                        }
                    }
                    if let Some(ns) = j.get("nameservers").and_then(|v| v.as_array()) {
                        let names: Vec<&str> = ns.iter().filter_map(|v| v.get("ldhName")?.as_str()).collect();
                        if !names.is_empty() { row("Nameservers", &names.join(", ")); }
                    }
                    if let Some(entities) = j.get("entities").and_then(|v| v.as_array()) {
                        for ent in entities {
                            if ent["roles"].as_array().map(|r| r.iter().any(|v| v.as_str() == Some("registrar"))).unwrap_or(false) {
                                if let Some(name) = ent.get("vcardArray")
                                    .and_then(|v| v.as_array()).and_then(|a| a.get(1))
                                    .and_then(|v| v.as_array())
                                    .and_then(|a| a.iter().find(|i| i.as_array().and_then(|x| x.first()).and_then(|v| v.as_str()) == Some("fn")))
                                    .and_then(|i| i.as_array()).and_then(|a| a.last())
                                    .and_then(|v| v.as_str()) {
                                    row("Registrar", name);
                                }
                            }
                        }
                    }
                    println!("\n  {} full data: https://rdap.org/domain/{}", "↳".magenta(), domain);
                }
            } else {
                println!("  [!] domain not found or rdap unavailable");
            }
        }
        Err(e) => { sp.finish_and_clear(); println!("  [!] {}", e); }
    }
    Ok(())
}

// ═══════════════════════════════════════════════════════════════════════════════
// MODULE: PHONE
// ═══════════════════════════════════════════════════════════════════════════════

async fn phone_mode(cfg: &Config, number: &str) -> Result<(), Box<dyn Error>> {
    section(&format!("phone lookup: {}", number.yellow().bold()));
    let clean: String = number.chars().filter(|c| c.is_ascii_digit() || *c == '+').collect();
    let digits = clean.chars().filter(|c| c.is_ascii_digit()).count();
    row("Number", &clean);
    row("Digits", &digits.to_string());
    row("E.164 valid", if digits >= 7 && digits <= 15 { "yes" } else { "suspicious length" });
    let country = detect_country_prefix(&clean);
    row("Country", &country);

    let client = cfg.build_client()?;
    let url = format!("https://api.country.is/{}", clean.trim_start_matches('+'));
    if let Ok(res) = client.get(&url).send().await {
        if let Ok(j) = res.json::<Value>().await {
            if let Some(cc) = j.get("country").and_then(|v| v.as_str()) { row("Country Code", &cc.yellow().to_string()); }
        }
    }

    section("lookup links");
    let n = clean.trim_start_matches('+');
    println!("  {} Truecaller:  https://www.truecaller.com/search/us/{}", "→".cyan(), n);
    println!("  {} Sync.me:     https://sync.me/search/?number={}", "→".cyan(), clean);
    println!("  {} 800Notes:    https://800notes.com/Phone.aspx/{}", "→".cyan(), clean);
    println!("  {} NumLookup:   https://www.numlookup.com/?number={}", "→".cyan(), clean);
    println!("  {} Phoneinfoga: https://phoneinfoga.crvx.fr/#/{}", "→".cyan(), clean);
    Ok(())
}

fn detect_country_prefix(number: &str) -> String {
    let n = number.trim_start_matches('+');
    let prefixes: &[(&str, &str)] = &[
        ("1","USA/Canada"),("7","Russia/Kazakhstan"),("20","Egypt"),("27","South Africa"),
        ("30","Greece"),("31","Netherlands"),("32","Belgium"),("33","France"),("34","Spain"),
        ("36","Hungary"),("39","Italy"),("40","Romania"),("41","Switzerland"),("43","Austria"),
        ("44","UK"),("45","Denmark"),("46","Sweden"),("47","Norway"),("48","Poland"),("49","Germany"),
        ("51","Peru"),("52","Mexico"),("54","Argentina"),("55","Brazil"),("56","Chile"),("57","Colombia"),
        ("58","Venezuela"),("60","Malaysia"),("61","Australia"),("62","Indonesia"),("63","Philippines"),
        ("64","New Zealand"),("65","Singapore"),("66","Thailand"),("81","Japan"),("82","South Korea"),
        ("84","Vietnam"),("86","China"),("90","Turkey"),("91","India"),("92","Pakistan"),("94","Sri Lanka"),
        ("95","Myanmar"),("98","Iran"),("212","Morocco"),("213","Algeria"),("216","Tunisia"),("218","Libya"),
        ("234","Nigeria"),("254","Kenya"),("255","Tanzania"),("256","Uganda"),("260","Zambia"),("263","Zimbabwe"),
        ("351","Portugal"),("352","Luxembourg"),("353","Ireland"),("354","Iceland"),("355","Albania"),
        ("358","Finland"),("359","Bulgaria"),("370","Lithuania"),("371","Latvia"),("372","Estonia"),
        ("373","Moldova"),("374","Armenia"),("375","Belarus"),("376","Andorra"),("380","Ukraine"),
        ("381","Serbia"),("382","Montenegro"),("385","Croatia"),("386","Slovenia"),("387","Bosnia"),
        ("389","North Macedonia"),("420","Czech Republic"),("421","Slovakia"),("966","Saudi Arabia"),
        ("971","UAE"),("972","Israel"),("994","Azerbaijan"),("995","Georgia"),("996","Kyrgyzstan"),("998","Uzbekistan"),
    ];
    for len in [3usize, 2, 1] {
        if n.len() >= len {
            let prefix = &n[..len];
            if let Some((p, c)) = prefixes.iter().find(|(p, _)| *p == prefix) {
                return format!("+{} — {}", p, c);
            }
        }
    }
    "Unknown".into()
}

// ═══════════════════════════════════════════════════════════════════════════════
// MODULE: WAYBACK
// ═══════════════════════════════════════════════════════════════════════════════

async fn wayback_mode(cfg: &Config, url: &str) -> Result<(), Box<dyn Error>> {
    section(&format!("wayback machine: {}", url.yellow().bold()));
    let sp = spinner("fetching snapshots...");
    let client = cfg.build_client()?;
    let clean = strip_proto(url);
    let api = format!("https://web.archive.org/cdx/search/cdx?url={}&output=json&limit=15&fl=timestamp,statuscode,mimetype,length,original&filter=statuscode:200&collapse=digest", clean);

    match client.get(&api).send().await {
        Ok(res) => {
            sp.finish_and_clear();
            if let Ok(json) = res.json::<Vec<Vec<String>>>().await {
                if json.len() <= 1 { println!("  [!] no snapshots found."); return Ok(()); }
                println!("\n  [{}] {} snapshots found:\n", "+".green().bold(), (json.len()-1).to_string().green().bold());
                for row_data in json.iter().skip(1) {
                    if row_data.len() < 5 { continue; }
                    let ts = &row_data[0];
                    let mime = &row_data[2];
                    let size = &row_data[3];
                    let orig = &row_data[4];
                    let fmt_ts = if ts.len() >= 14 {
                        format!("{}-{}-{} {}:{}:{}", &ts[0..4], &ts[4..6], &ts[6..8], &ts[8..10], &ts[10..12], &ts[12..14])
                    } else { ts.clone() };
                    let link = format!("https://web.archive.org/web/{}/{}", ts, orig);
                    println!("  {} {}", "●".cyan(), fmt_ts.bold());
                    println!("    {} {}  {} {} bytes", "type:".dimmed(), mime, "size:".dimmed(), size);
                    println!("    {}", link.cyan());
                    println!();
                }
            }
        }
        Err(e) => { sp.finish_and_clear(); println!("  [!] {}", e); }
    }
    Ok(())
}

// ═══════════════════════════════════════════════════════════════════════════════
// MODULE: TLS / CDN BYPASS
// ═══════════════════════════════════════════════════════════════════════════════

async fn tls_mode(cfg: &Config, domain: &str) -> Result<(), Box<dyn Error>> {
    section(&format!("tls/cdn fingerprint: {}", domain.yellow().bold()));
    println!("  {}", "trying to find real IP behind CDN...".dimmed());
    let client = cfg.build_client()?;
    let cf_ranges = ["104.16.","104.17.","104.18.","104.19.","104.20.","104.21.",
        "172.64.","172.65.","172.66.","172.67.","172.68.","172.69.",
        "172.70.","172.71.","188.114.","190.93.","197.234.","198.41."];

    let mut current_ips: Vec<String> = vec![];
    let dns_url = format!("https://dns.google/resolve?name={}&type=A", domain);
    if let Ok(res) = client.get(&dns_url).send().await {
        if let Ok(j) = res.json::<Value>().await {
            if let Some(answers) = j.get("Answer").and_then(|v| v.as_array()) {
                for ans in answers { if let Some(ip) = ans["data"].as_str() { current_ips.push(ip.to_string()); } }
            }
        }
    }
    section("current A records");
    for ip in &current_ips {
        let is_cf = cf_ranges.iter().any(|r| ip.starts_with(r));
        if is_cf { println!("  {} {}  {}", "→".magenta(), ip.yellow(), "[Cloudflare]".red().bold()); }
        else     { println!("  {} {}", "→".magenta(), ip.green().bold()); }
    }
    sleep(Duration::from_millis(200)).await;

    let spf_url = format!("https://dns.google/resolve?name={}&type=TXT", domain);
    let mut spf_ips: Vec<String> = vec![];
    if let Ok(res) = client.get(&spf_url).send().await {
        if let Ok(j) = res.json::<Value>().await {
            if let Some(answers) = j.get("Answer").and_then(|v| v.as_array()) {
                for ans in answers {
                    if let Some(data) = ans["data"].as_str() {
                        if data.contains("spf") || data.contains("ip4") {
                            for part in data.split_whitespace() {
                                if part.starts_with("ip4:") { spf_ips.push(part.trim_start_matches("ip4:").to_string()); }
                            }
                        }
                    }
                }
            }
        }
    }
    if !spf_ips.is_empty() {
        section("spf → possible mail server ips");
        for ip in &spf_ips { println!("  {} {}", "→".green(), ip.green().bold()); }
    }
    sleep(Duration::from_millis(200)).await;

    let ht_url = format!("https://api.hackertarget.com/hostsearch/?q={}", domain);
    if let Ok(res) = client.get(&ht_url).send().await {
        if let Ok(text) = res.text().await {
            if !text.contains("API count") && !text.contains("error") {
                let lines: Vec<&str> = text.lines().take(20).collect();
                if !lines.is_empty() {
                    section("subdomains with ips");
                    for line in lines {
                        let parts: Vec<&str> = line.splitn(2, ',').collect();
                        if parts.len() == 2 { println!("  {} {} → {}", "↳".magenta(), parts[0], parts[1]); }
                    }
                }
            }
        }
    }

    let behind_cf = current_ips.iter().any(|ip| cf_ranges.iter().any(|r| ip.starts_with(r)));
    println!();
    if behind_cf {
        println!("  {} {}", "⚠".yellow().bold(), "domain is behind Cloudflare — real IP is hidden".yellow().bold());
        println!("  {} check subdomains (mail. direct. ftp.) and SPF IPs above", "↳".magenta());
        println!("  {} https://search.censys.io/search?resource=hosts&q={}", "↳".magenta(), domain);
    } else {
        println!("  {} {}", "✓".green(), "no major CDN on primary A records".green());
    }
    Ok(())
}

// ═══════════════════════════════════════════════════════════════════════════════
// MODULE: PORT SCANNER
// ═══════════════════════════════════════════════════════════════════════════════

async fn port_scan_mode(host: &str, profile: &str) -> Result<(), Box<dyn Error>> {
    section(&format!("port scan: {} ({})", host.yellow().bold(), profile.cyan()));
    let ports: Vec<u16> = match profile {
        "web"     => vec![80,443,8080,8443,3000,4000,5000,8000,8888,9000,9443,4433],
        "full"    => (1..=1024).collect(),
        "top1000" => (1..=1000).collect(),
        _ => vec![
            21,22,23,25,53,80,110,111,119,135,139,143,194,443,445,
            465,587,993,995,1080,1194,1433,1521,2083,2087,2096,2222,
            3000,3306,3389,4333,5432,5900,6379,6881,8080,8443,8888,
            9000,9200,9418,10000,27017,50070,61616,
        ],
    };
    let host_clean = strip_proto(host);
    let total = ports.len() as u64;
    let pb = ProgressBar::new(total);
    pb.set_style(bar_style());
    pb.set_message("scanning...");
    let open: Arc<Mutex<Vec<(u16, &'static str)>>> = Arc::new(Mutex::new(vec![]));
    let start = Instant::now();

    let mut tasks = vec![];
    for port in ports {
        let h = host_clean.clone();
        let op = Arc::clone(&open);
        let pb2 = pb.clone();
        tasks.push(tokio::spawn(async move {
            let addr_str = format!("{}:{}", h, port);
            let timeout = Duration::from_millis(700);
            let is_open = tokio::time::timeout(timeout, async {
                match addr_str.parse::<SocketAddr>() {
                    Ok(sa) => TcpStream::connect_timeout(&sa, timeout).is_ok(),
                    Err(_) => TcpStream::connect(&addr_str).is_ok(),
                }
            }).await.unwrap_or(false);
            if is_open { op.lock().unwrap().push((port, port_service(port))); }
            pb2.inc(1);
        }));
    }
    join_all(tasks).await;
    pb.finish_with_message("done");

    let mut res = open.lock().unwrap();
    res.sort_by_key(|(p, _)| *p);
    println!();
    if res.is_empty() {
        println!("  [!] no open ports found.");
    } else {
        println!("  [{}] {} open port(s):\n", "+".green().bold(), res.len().to_string().green().bold());
        for (port, svc) in res.iter() {
            println!("  {} {:<7} {}", "●".green(), port.to_string().cyan().bold(), svc.dimmed());
        }
    }
    println!("\n  {} scanned {} ports in {:.2}s", "✓".green(), total, start.elapsed().as_secs_f64());
    Ok(())
}

fn port_service(p: u16) -> &'static str {
    match p {
        21=>"FTP",22=>"SSH",23=>"Telnet",25=>"SMTP",53=>"DNS",80=>"HTTP",110=>"POP3",
        111=>"RPC",119=>"NNTP",135=>"RPC/DCOM",139=>"NetBIOS",143=>"IMAP",194=>"IRC",
        443=>"HTTPS",445=>"SMB",465=>"SMTPS",587=>"SMTP submission",993=>"IMAPS",995=>"POP3S",
        1080=>"SOCKS Proxy",1194=>"OpenVPN",1433=>"MSSQL",1521=>"Oracle DB",2083=>"cPanel SSL",
        2087=>"WHM SSL",2096=>"Webmail SSL",2222=>"SSH alt",3000=>"Dev server",3306=>"MySQL",
        3389=>"RDP",4333=>"mSQL",4433=>"HTTPS alt",5432=>"PostgreSQL",5900=>"VNC",6379=>"Redis",
        6881=>"BitTorrent",8080=>"HTTP proxy/alt",8443=>"HTTPS alt",8888=>"Jupyter/HTTP alt",
        9000=>"PHP-FPM/SonarQube",9200=>"Elasticsearch",9418=>"Git",9443=>"HTTPS alt",
        10000=>"Webmin",27017=>"MongoDB",50070=>"Hadoop NameNode",61616=>"ActiveMQ",_=>"unknown",
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// MODULE: SITE ANALYZER
// ═══════════════════════════════════════════════════════════════════════════════

async fn site_mode(cfg: &Config, url: &str) -> Result<(), Box<dyn Error>> {
    let mut url = url.to_string();
    if !url.starts_with("http") { url = format!("https://{}", url); }
    section(&format!("site analysis: {}", url.yellow().bold()));
    let sp = spinner("fetching...");
    let client = cfg.build_client()?;

    match client.get(&url).send().await {
        Ok(res) => {
            sp.finish_and_clear();
            println!("  status: {}", res.status().to_string().yellow().bold());
            let headers = res.headers().clone();

            section("security headers");
            let sec = [
                ("content-security-policy","CSP"),("strict-transport-security","HSTS"),
                ("x-frame-options","X-Frame-Options"),("x-content-type-options","X-Content-Type-Options"),
                ("referrer-policy","Referrer-Policy"),("permissions-policy","Permissions-Policy"),
            ];
            for (h, label) in &sec {
                if headers.contains_key(*h) { println!("  {} {}", "✓".green(), label.bold()); }
                else { println!("  {} {}  {}", "✗".red(), label.bold(), "(missing)".dimmed()); }
            }

            section("response headers");
            for (k, v) in headers.iter() {
                if let Ok(val) = v.to_str() { println!("  {}: {}", k.as_str().cyan(), val.dimmed()); }
            }

            if let Ok(body) = res.text().await {
                let doc = Html::parse_document(&body);
                section("meta info");
                if let Ok(sel) = Selector::parse("title") {
                    if let Some(t) = doc.select(&sel).next() { row("Title", t.inner_html().trim()); }
                }
                if let Ok(sel) = Selector::parse("meta") {
                    for m in doc.select(&sel) {
                        let name = m.value().attr("name").or(m.value().attr("property")).unwrap_or("");
                        let content = m.value().attr("content").unwrap_or("");
                        if !name.is_empty() && !content.is_empty() { row(name, content); }
                    }
                }
                section("tech stack detection");
                let body_l = body.to_lowercase();
                let sigs: &[(&str, &str)] = &[
                    ("wp-content","WordPress"),("wp-json","WordPress REST API"),("drupal","Drupal"),
                    ("joomla","Joomla"),("shopify","Shopify"),("gatsby","Gatsby"),("next.js","Next.js"),
                    ("nuxt","Nuxt.js"),("react","React"),("angular","Angular"),("vue","Vue.js"),
                    ("svelte","Svelte"),("ember","Ember.js"),("backbone","Backbone.js"),("bootstrap","Bootstrap"),
                    ("tailwind","Tailwind CSS"),("bulma","Bulma"),("foundation","Foundation"),("jquery","jQuery"),
                    ("lodash","Lodash"),("google-analytics","Google Analytics"),("gtag","Google Tag Manager"),
                    ("cloudflare","Cloudflare"),("nginx","Nginx"),("apache","Apache"),("laravel","Laravel"),
                    ("django","Django"),("rails","Ruby on Rails"),("flask","Flask"),("express","Express.js"),
                    ("fastapi","FastAPI"),("graphql","GraphQL"),("prisma","Prisma"),("supabase","Supabase"),
                    ("firebase","Firebase"),("stripe","Stripe"),("intercom","Intercom"),("hotjar","Hotjar"),
                    ("recaptcha","reCAPTCHA"),("cloudfront","AWS CloudFront"),("akamai","Akamai"),
                ];
                let mut detected = vec![];
                for (sig, name) in sigs { if body_l.contains(sig) { detected.push(*name); } }
                if detected.is_empty() { println!("  {}", "no common stack detected".dimmed()); }
                else { for t in &detected { println!("  {} {}", "✓".green(), t.bold()); } }

                section("links (first 15)");
                if let Ok(sel) = Selector::parse("a[href]") {
                    let mut count = 0;
                    for link in doc.select(&sel) {
                        if count >= 15 { break; }
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
        Err(e) => { sp.finish_and_clear(); println!("  [!] {}", e); }
    }
    Ok(())
}

// ═══════════════════════════════════════════════════════════════════════════════
// MODULE: EXIF
// ═══════════════════════════════════════════════════════════════════════════════

async fn exif_mode(cfg: &Config, path: &str) -> Result<(), Box<dyn Error>> {
    section(&format!("exif extraction: {}", path.yellow().bold()));
    let img_data = match load_bytes(cfg, path).await {
        Ok(d) => d,
        Err(e) => { println!("  [!] {}", e); return Ok(()); }
    };
    print_exif(&img_data);
    Ok(())
}

// Shared loader used by exif + meta
async fn load_bytes(cfg: &Config, path: &str) -> Result<Vec<u8>, String> {
    if path.starts_with("http") {
        let client = cfg.build_client().map_err(|e| e.to_string())?;
        let sp = spinner("downloading...");
        match client.get(path).send().await {
            Ok(res) => {
                sp.finish_and_clear();
                if res.status().is_success() {
                    res.bytes().await.map(|b| b.to_vec()).map_err(|e| e.to_string())
                } else { Err(format!("download failed: {}", res.status())) }
            }
            Err(e) => { sp.finish_and_clear(); Err(e.to_string()) }
        }
    } else {
        fs::read(path).map_err(|e| format!("cannot read file: {}", e))
    }
}

fn print_exif(img_data: &[u8]) {
    section("exif data");
    let mut cursor = Cursor::new(img_data);
    match exif::Reader::new().read_from_container(&mut cursor) {
        Ok(exif_data) => {
            let fields: Vec<_> = exif_data.fields().collect();
            if fields.is_empty() { println!("  {}", "no EXIF found — image may have been stripped.".yellow()); return; }
            let mut lat_str = String::new();
            let mut lon_str = String::new();
            let mut has_gps = false;
            for f in &fields {
                println!("  {}: {}", f.tag.to_string().cyan(), f.display_value().to_string().dimmed());
                let t = f.tag.to_string();
                if t.contains("GPSLatitude") && !t.contains("Ref") { lat_str = f.display_value().to_string(); has_gps = true; }
                if t.contains("GPSLongitude") && !t.contains("Ref") { lon_str = f.display_value().to_string(); }
            }
            if has_gps && !lat_str.is_empty() {
                println!("\n  {} {} GPS coordinates found!", "⚠".yellow().bold(), "privacy warning:".red().bold());
                println!("    lat: {}  lon: {}", lat_str.yellow(), lon_str.yellow());
                println!("    map: https://maps.google.com/?q={},{}", lat_str.replace(' ',""), lon_str.replace(' ',""));
            }
        }
        Err(_) => println!("  {}", "no EXIF data or unsupported format.".yellow()),
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// MODULE: GIT — GitHub deep recon
// ═══════════════════════════════════════════════════════════════════════════════

async fn git_mode(cfg: &Config, username: &str) -> Result<(), Box<dyn Error>> {
    section(&format!("github recon: {}", username.yellow().bold()));
    let token = cfg.github_token.clone().unwrap_or_default();
    let client = cfg.build_client()?;
    let auth = |rb: reqwest::RequestBuilder| -> reqwest::RequestBuilder {
        let rb = rb.header("Accept", "application/vnd.github+json").header("User-Agent", "RustCohle");
        if !token.is_empty() { rb.header("Authorization", format!("Bearer {}", token)) } else { rb }
    };

    let sp = spinner("fetching profile...");
    let profile_url = format!("https://api.github.com/users/{}", username);
    match auth(client.get(&profile_url)).send().await {
        Ok(res) => {
            sp.finish_and_clear();
            if res.status().is_success() {
                if let Ok(j) = res.json::<Value>().await {
                    section("profile");
                    for (k, label) in [("name","Name"),("bio","Bio"),("email","Email"),("location","Location"),
                        ("company","Company"),("blog","Blog"),("twitter_username","Twitter"),
                        ("public_repos","Public Repos"),("public_gists","Public Gists"),
                        ("followers","Followers"),("following","Following"),
                        ("created_at","Created"),("updated_at","Updated")] {
                        if let Some(v) = j.get(k) {
                            let s = if v.is_string() { v.as_str().unwrap().to_string() } else { v.to_string() };
                            if !s.is_empty() && s != "null" && s != "\"\"" { row(label, &s); }
                        }
                    }
                }
            } else {
                println!("  [!] user not found or API rate limit hit.");
                println!("      set github_token in config.toml for higher limits.");
                return Ok(());
            }
        }
        Err(e) => { sp.finish_and_clear(); println!("  [!] {}", e); return Ok(()); }
    }

    let repos_url = format!("https://api.github.com/users/{}/repos?per_page=30&sort=updated", username);
    if let Ok(res) = auth(client.get(&repos_url)).send().await {
        if let Ok(repos) = res.json::<Vec<Value>>().await {
            section(&format!("repositories ({} shown)", repos.len().min(30)));
            for repo in repos.iter().take(30) {
                let name  = repo["name"].as_str().unwrap_or("?");
                let desc  = repo["description"].as_str().unwrap_or("");
                let lang  = repo["language"].as_str().unwrap_or("?");
                let stars = repo["stargazers_count"].as_u64().unwrap_or(0);
                let forks = repo["forks_count"].as_u64().unwrap_or(0);
                println!("  {} {:<35} {} ★{}  ⑂{}", "●".cyan(), name.bold(), lang.yellow(), stars, forks);
                if !desc.is_empty() { println!("    {}", desc.dimmed()); }
            }
        }
    }
    sleep(Duration::from_millis(300)).await;

    let events_url = format!("https://api.github.com/users/{}/events/public?per_page=100", username);
    let mut found_emails: HashSet<String> = HashSet::new();
    if let Ok(res) = auth(client.get(&events_url)).send().await {
        if let Ok(events) = res.json::<Vec<Value>>().await {
            for event in &events {
                if event["type"].as_str() == Some("PushEvent") {
                    if let Some(commits) = event["payload"]["commits"].as_array() {
                        for commit in commits {
                            if let Some(email) = commit["author"]["email"].as_str() {
                                if !email.contains("noreply.github.com") && !email.is_empty() {
                                    found_emails.insert(email.to_string());
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    if !found_emails.is_empty() {
        section("emails extracted from commits");
        for email in &found_emails { println!("  {} {}", "●".red().bold(), email.red().bold()); }
    } else {
        section("emails from commits");
        println!("  {} no emails found (may use noreply or private commits)", "–".dimmed());
    }
    sleep(Duration::from_millis(300)).await;

    // SSH/GPG keys are public — useful for fingerprinting
    let keys_url = format!("https://api.github.com/users/{}/keys", username);
    if let Ok(res) = auth(client.get(&keys_url)).send().await {
        if let Ok(keys) = res.json::<Vec<Value>>().await {
            if !keys.is_empty() {
                section(&format!("public ssh keys ({})", keys.len()));
                for k in &keys {
                    if let Some(key) = k["key"].as_str() {
                        let preview: String = key.chars().take(50).collect();
                        println!("  {} {}…", "🔑".yellow(), preview.dimmed());
                    }
                }
                println!("  {} full keys: https://github.com/{}.keys", "↳".magenta(), username);
            }
        }
    }
    sleep(Duration::from_millis(300)).await;

    let gists_url = format!("https://api.github.com/users/{}/gists?per_page=10", username);
    if let Ok(res) = auth(client.get(&gists_url)).send().await {
        if let Ok(gists) = res.json::<Vec<Value>>().await {
            if !gists.is_empty() {
                section(&format!("gists ({} shown)", gists.len()));
                for g in gists.iter().take(10) {
                    let desc    = g["description"].as_str().unwrap_or("(no description)");
                    let url     = g["html_url"].as_str().unwrap_or("");
                    let updated = g["updated_at"].as_str().unwrap_or("?");
                    println!("  {} {}  {}", "●".cyan(), desc.bold(), updated.dimmed());
                    println!("    {}", url.cyan());
                }
            }
        }
    }
    sleep(Duration::from_millis(300)).await;

    let orgs_url = format!("https://api.github.com/users/{}/orgs", username);
    if let Ok(res) = auth(client.get(&orgs_url)).send().await {
        if let Ok(orgs) = res.json::<Vec<Value>>().await {
            if !orgs.is_empty() {
                section("organizations");
                for org in &orgs {
                    let name = org["login"].as_str().unwrap_or("?");
                    let desc = org["description"].as_str().unwrap_or("");
                    println!("  {} {:<30} {}", "●".cyan(), name.bold(), desc.dimmed());
                }
            }
        }
    }
    println!("\n  {} set github_token for higher API rate limits", "↳".magenta());
    Ok(())
}

// ═══════════════════════════════════════════════════════════════════════════════
// MODULE: CRT — subdomain enumeration + takeover detection
// ═══════════════════════════════════════════════════════════════════════════════

async fn crt_mode(cfg: &Config, domain: &str) -> Result<(), Box<dyn Error>> {
    section(&format!("subdomain enumeration: {}", domain.yellow().bold()));
    let client = cfg.build_client()?;
    let mut all_subs: HashSet<String> = HashSet::new();
    let start = Instant::now();
    let sp = spinner("querying crt.sh...");

    let crt_url = format!("https://crt.sh/?q=%.{}&output=json", domain);
    if let Some(res) = get_with_retry(&client, &crt_url, cfg.max_retries).await {
        if let Ok(j) = res.json::<Vec<Value>>().await {
            for entry in &j {
                if let Some(name) = entry["name_value"].as_str() {
                    for sub in name.split('\n') {
                        let s = sub.trim().to_string();
                        if !s.is_empty() && !s.starts_with('*') && s.ends_with(domain) { all_subs.insert(s); }
                    }
                }
            }
        }
    }
    sp.set_message("querying hackertarget...");
    sleep(Duration::from_millis(300)).await;

    let ht_url = format!("https://api.hackertarget.com/hostsearch/?q={}", domain);
    if let Ok(res) = client.get(&ht_url).send().await {
        if let Ok(text) = res.text().await {
            if !text.contains("API count") && !text.contains("error") {
                for line in text.lines() {
                    let parts: Vec<&str> = line.splitn(2, ',').collect();
                    if !parts.is_empty() && parts[0].ends_with(domain) { all_subs.insert(parts[0].to_string()); }
                }
            }
        }
    }
    sp.set_message("querying alienvault...");
    sleep(Duration::from_millis(300)).await;

    let otx_url = format!("https://otx.alienvault.com/api/v1/indicators/domain/{}/passive_dns", domain);
    if let Ok(res) = client.get(&otx_url).send().await {
        if let Ok(j) = res.json::<Value>().await {
            if let Some(entries) = j.get("passive_dns").and_then(|v| v.as_array()) {
                for entry in entries {
                    if let Some(hostname) = entry["hostname"].as_str() {
                        if hostname.ends_with(domain) { all_subs.insert(hostname.to_string()); }
                    }
                }
            }
        }
    }
    sp.finish_and_clear();

    let mut subs: Vec<String> = all_subs.into_iter().collect();
    subs.sort();
    println!("\n  [{}] {} unique subdomains found:\n", "+".green().bold(), subs.len().to_string().green().bold());
    for sub in &subs { println!("  {} {}", "↳".magenta(), sub.cyan()); }

    // Subdomain takeover detection: check CNAMEs pointing at unclaimed services
    section("subdomain takeover scan");
    println!("  {}", "checking CNAMEs for dangling/unclaimed services...".dimmed());
    let fingerprints: &[(&str, &str)] = &[
        ("github.io",          "GitHub Pages"),
        ("herokuapp.com",      "Heroku"),
        ("herokudns.com",      "Heroku"),
        ("amazonaws.com",      "AWS S3/EC2"),
        ("cloudfront.net",     "AWS CloudFront"),
        ("azurewebsites.net",  "Azure"),
        ("cloudapp.net",       "Azure"),
        ("trafficmanager.net", "Azure Traffic Manager"),
        ("ghost.io",           "Ghost"),
        ("wordpress.com",      "WordPress"),
        ("pantheonsite.io",    "Pantheon"),
        ("fastly.net",         "Fastly"),
        ("netlify.app",        "Netlify"),
        ("netlify.com",        "Netlify"),
        ("readthedocs.io",     "ReadTheDocs"),
        ("surge.sh",           "Surge"),
        ("bitbucket.io",       "Bitbucket"),
        ("zendesk.com",        "Zendesk"),
        ("helpscoutdocs.com",  "HelpScout"),
        ("statuspage.io",      "StatusPage"),
        ("uservoice.com",      "UserVoice"),
        ("wpengine.com",       "WP Engine"),
        ("shopify.com",        "Shopify"),
        ("myshopify.com",      "Shopify"),
        ("unbouncepages.com",  "Unbounce"),
        ("desk.com",           "Desk"),
    ];

    let check_subs: Vec<String> = subs.iter().take(40).cloned().collect();
    let mut potential = 0;
    for sub in &check_subs {
        let cname_url = format!("https://dns.google/resolve?name={}&type=CNAME", sub);
        sleep(Duration::from_millis(50)).await;
        if let Ok(res) = client.get(&cname_url).send().await {
            if let Ok(j) = res.json::<Value>().await {
                if let Some(answers) = j.get("Answer").and_then(|v| v.as_array()) {
                    for ans in answers {
                        if let Some(cname) = ans["data"].as_str() {
                            for (fp, service) in fingerprints {
                                if cname.contains(fp) {
                                    // CNAME points at a known service — verify whether it still resolves to an A record
                                    let a_url = format!("https://dns.google/resolve?name={}&type=A", sub);
                                    let mut resolves = false;
                                    if let Ok(ar) = client.get(&a_url).send().await {
                                        if let Ok(aj) = ar.json::<Value>().await {
                                            resolves = aj.get("Answer")
                                                .and_then(|a| a.as_array())
                                                .map(|x| !x.is_empty())
                                                .unwrap_or(false);
                                        }
                                    }
                                    let flag = if resolves { "→".cyan() } else { "⚠ DANGLING".red().bold() };
                                    println!("  {} {} {} {}", flag, sub.bold(), "CNAME→".dimmed(), format!("{} ({})", cname, service).yellow());
                                    if !resolves { potential += 1; }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    if potential == 0 {
        println!("  {} no obvious takeover candidates in first {} subdomains", "✓".green(), check_subs.len());
    } else {
        println!("\n  {} {} potential takeover target(s) — verify manually!", "⚠".red().bold(), potential);
    }

    println!("\n  {} done in {:.2}s", "✓".green(), start.elapsed().as_secs_f64());
    Ok(())
}

// ═══════════════════════════════════════════════════════════════════════════════
// MODULE: HEADERS + WAF/CDN detection
// ═══════════════════════════════════════════════════════════════════════════════

async fn headers_mode(cfg: &Config, url: &str) -> Result<(), Box<dyn Error>> {
    let mut url = url.to_string();
    if !url.starts_with("http") { url = format!("https://{}", url); }
    section(&format!("headers + waf detection: {}", url.yellow().bold()));
    let client = cfg.build_client()?;
    let sp = spinner("fetching headers...");

    match client.get(&url).send().await {
        Ok(res) => {
            sp.finish_and_clear();
            println!("  status: {}", res.status().to_string().yellow().bold());
            section("all response headers");
            let headers = res.headers().clone();
            let mut header_map: HashMap<String, String> = HashMap::new();
            for (k, v) in headers.iter() {
                if let Ok(val) = v.to_str() {
                    println!("  {}: {}", k.as_str().cyan(), val);
                    header_map.insert(k.as_str().to_lowercase(), val.to_string());
                }
            }

            section("waf / cdn detection");
            let waf_sigs: &[(&str, &str, &str)] = &[
                ("cf-ray","header","Cloudflare"),("x-sucuri-id","header","Sucuri WAF"),
                ("x-sucuri-cache","header","Sucuri WAF"),("x-fw-server","header","Fastly WAF"),
                ("x-cache","header","Varnish/CDN cache"),("x-powered-by-plesk","header","Plesk"),
                ("x-amz-cf-id","header","AWS CloudFront"),("x-amz-request-id","header","AWS"),
                ("x-azure-ref","header","Azure CDN"),("x-akamai-transformed","header","Akamai"),
                ("x-kong-proxy-latency","header","Kong API Gateway"),("x-envoy-upstream","header","Envoy/Istio"),
                ("x-iinfo","header","Incapsula/Imperva WAF"),("x-cdn","header","Generic CDN"),
                ("server","cloudflare","Cloudflare (server)"),("server","nginx","Nginx"),
                ("server","apache","Apache"),("server","litespeed","LiteSpeed"),
                ("server","openresty","OpenResty/Nginx"),("server","caddy","Caddy"),
                ("x-powered-by","asp.net","ASP.NET"),("x-powered-by","php","PHP"),
                ("x-powered-by","express","Express.js"),
            ];
            let mut detected: Vec<&str> = vec![];
            for (hk, sig, name) in waf_sigs {
                if *sig == "header" {
                    if header_map.contains_key(*hk) && !detected.contains(name) {
                        detected.push(name);
                        println!("  {} {} {}", "⚑".yellow().bold(), name.bold(), format!("({})", hk).dimmed());
                    }
                } else if let Some(val) = header_map.get(*hk) {
                    if val.to_lowercase().contains(*sig) && !detected.contains(name) {
                        detected.push(name);
                        println!("  {} {} {}", "⚑".yellow().bold(), name.bold(), format!("({})", val).dimmed());
                    }
                }
            }
            if detected.is_empty() { println!("  {} nothing detected", "–".dimmed()); }

            section("security header score");
            let sec_headers: [(&str, &str, u8); 6] = [
                ("content-security-policy","CSP",5),("strict-transport-security","HSTS",3),
                ("x-frame-options","X-Frame-Options",2),("x-content-type-options","X-Content-Type",2),
                ("referrer-policy","Referrer-Policy",2),("permissions-policy","Permissions-Policy",1),
            ];
            let mut score: u8 = 0;
            for (h, label, pts) in &sec_headers {
                if header_map.contains_key(*h) {
                    score += *pts;
                    println!("  {} {:<28} +{} pt", "✓".green(), label.bold(), pts);
                } else {
                    println!("  {} {:<28} {} missing", "✗".red(), label.bold(), "–".dimmed());
                }
            }
            let grade = match score {
                13..=15 => "A+".green().bold().to_string(),
                10..=12 => "A".green().to_string(),
                7..=9   => "B".yellow().to_string(),
                4..=6   => "C".yellow().to_string(),
                _       => "F".red().bold().to_string(),
            };
            println!("\n  security score: {}/15 → grade: {}", score, grade);
        }
        Err(e) => { sp.finish_and_clear(); println!("  [!] {}", e); }
    }
    Ok(())
}

// ═══════════════════════════════════════════════════════════════════════════════
// MODULE: PASTE SEARCH
// ═══════════════════════════════════════════════════════════════════════════════

async fn paste_mode(cfg: &Config, query: &str) -> Result<(), Box<dyn Error>> {
    section(&format!("paste search: {}", query.yellow().bold()));
    println!("  {}", "searching paste sites for mentions...".dimmed());
    let client = cfg.build_client()?;
    let encoded = urlencoding::encode(query);

    let psbdmp_url = format!("https://psbdmp.ws/api/search/{}", encoded);
    if let Ok(res) = client.get(&psbdmp_url).send().await {
        if let Ok(j) = res.json::<Value>().await {
            if let Some(data) = j.get("data").and_then(|v| v.as_array()) {
                if !data.is_empty() {
                    section(&format!("psbdmp.ws ({} results)", data.len()));
                    for entry in data.iter().take(10) {
                        let id   = entry["id"].as_str().unwrap_or("?");
                        let time = entry["time"].as_str().unwrap_or("?");
                        let tags = entry["tags"].as_str().unwrap_or("");
                        println!("  {} https://pastebin.com/{}", "●".cyan(), id);
                        println!("    {} {}  {}", "time:".dimmed(), time, tags.dimmed());
                    }
                } else {
                    println!("  {} psbdmp.ws: no results", "–".dimmed());
                }
            }
        }
    }

    section("manual search links");
    let sources: &[(&str, String)] = &[
        ("IntelligenceX", format!("https://intelx.io/?s={}", encoded)),
        ("Pastebin", format!("https://pastebin.com/search?q={}", encoded)),
        ("GrayhatWarfare", format!("https://grayhatwarfare.com/files?search={}", encoded)),
        ("PublicWWW", format!("https://publicwww.com/websites/{}/", encoded)),
        ("Google dorks", format!("https://www.google.com/search?q=site:pastebin.com+{}", encoded)),
    ];
    for (name, url) in sources {
        println!("  {} {:<18} {}", "→".cyan(), name.bold(), url.dimmed());
    }
    Ok(())
}

// ═══════════════════════════════════════════════════════════════════════════════
// MODULE: BANNER GRAB
// ═══════════════════════════════════════════════════════════════════════════════

async fn banner_mode(cfg: &Config, host: &str) -> Result<(), Box<dyn Error>> {
    section(&format!("banner grab: {}", host.yellow().bold()));
    let client = cfg.build_client()?;
    let host_clean = strip_proto(host);
    let grab_ports: &[(u16, &str)] = &[
        (80,"http"),(443,"https"),(8080,"http"),(8443,"https"),
    ];
    let pb = ProgressBar::new(grab_ports.len() as u64);
    pb.set_style(bar_style());

    for (port, proto) in grab_ports {
        let url = format!("{}://{}:{}", proto, host_clean, port);
        let timeout = Duration::from_secs(4);
        match tokio::time::timeout(timeout, client.get(&url).send()).await {
            Ok(Ok(res)) => {
                pb.suspend(|| {
                    println!("\n  {} port {} ({}):", "●".green(), port.to_string().cyan().bold(), proto);
                    println!("    status: {}", res.status().to_string().yellow());
                    for (k, v) in res.headers().iter() {
                        if let Ok(val) = v.to_str() {
                            match k.as_str() {
                                "server"|"x-powered-by"|"via"|"x-generator"|"content-type" => {
                                    println!("    {}: {}", k.as_str().cyan(), val);
                                }
                                _ => {}
                            }
                        }
                    }
                });
            }
            _ => {
                pb.suspend(|| {
                    println!("\n  {} port {} ({}): {}", "–".dimmed(), port, proto, "no response".dimmed());
                });
            }
        }
        pb.inc(1);
    }
    pb.finish_and_clear();
    Ok(())
}

// ═══════════════════════════════════════════════════════════════════════════════
// MODULE: REVERSE IP — domains on the same host (NEW)
// ═══════════════════════════════════════════════════════════════════════════════

async fn reverse_ip_mode(cfg: &Config, target: &str) -> Result<(), Box<dyn Error>> {
    section(&format!("reverse ip lookup: {}", target.yellow().bold()));
    let client = cfg.build_client()?;

    // Resolve domain → IP if needed
    let ip = match resolve_ip(&client, &strip_proto(target)).await {
        Some(ip) => ip,
        None => { println!("  [!] could not resolve target to an IP."); return Ok(()); }
    };
    if ip != target { row("Resolved IP", &ip); }

    let sp = spinner("querying reverse DNS sources...");
    let mut domains: HashSet<String> = HashSet::new();

    // 1. HackerTarget reverse IP
    let ht_url = format!("https://api.hackertarget.com/reverseiplookup/?q={}", ip);
    if let Ok(res) = client.get(&ht_url).send().await {
        if let Ok(text) = res.text().await {
            if !text.contains("API count") && !text.contains("error") && !text.to_lowercase().contains("no records") {
                for line in text.lines() {
                    let d = line.trim().to_string();
                    if !d.is_empty() && d.contains('.') { domains.insert(d); }
                }
            }
        }
    }
    sleep(Duration::from_millis(300)).await;

    // 2. AlienVault OTX passive DNS for the IP
    let otx_url = format!("https://otx.alienvault.com/api/v1/indicators/IPv4/{}/passive_dns", ip);
    if let Ok(res) = client.get(&otx_url).send().await {
        if let Ok(j) = res.json::<Value>().await {
            if let Some(entries) = j.get("passive_dns").and_then(|v| v.as_array()) {
                for entry in entries {
                    if let Some(hostname) = entry["hostname"].as_str() {
                        if hostname.contains('.') { domains.insert(hostname.to_string()); }
                    }
                }
            }
        }
    }
    sp.finish_and_clear();

    let mut list: Vec<String> = domains.into_iter().collect();
    list.sort();
    if list.is_empty() {
        println!("  {} no co-hosted domains found (IP may be dedicated or behind CDN)", "–".dimmed());
    } else {
        println!("\n  [{}] {} domains sharing this IP:\n", "+".green().bold(), list.len().to_string().green().bold());
        for d in &list { println!("  {} {}", "↳".magenta(), d.cyan()); }
        if list.len() > 5 {
            println!("\n  {} {}", "note:".yellow(), "many shared domains usually means shared hosting / CDN".dimmed());
        }
    }
    Ok(())
}

// ═══════════════════════════════════════════════════════════════════════════════
// MODULE: ASN — announced prefixes + org (NEW)
// ═══════════════════════════════════════════════════════════════════════════════

async fn asn_mode(cfg: &Config, target: &str) -> Result<(), Box<dyn Error>> {
    section(&format!("asn lookup: {}", target.yellow().bold()));
    let client = cfg.build_client()?;

    // Determine the ASN. If target is an IP, resolve to ASN first via ip-api.
    let asn_number: String = if target.to_uppercase().starts_with("AS") {
        target[2..].to_string()
    } else if target.chars().all(|c| c.is_ascii_digit()) {
        target.to_string()
    } else {
        // treat as IP or domain → resolve to IP → ASN
        let ip = resolve_ip(&client, &strip_proto(target)).await.unwrap_or_else(|| target.to_string());
        let mut found = String::new();
        let url = format!("http://ip-api.com/json/{}?fields=as", ip);
        if let Ok(res) = client.get(&url).send().await {
            if let Ok(j) = res.json::<Value>().await {
                if let Some(as_str) = j.get("as").and_then(|v| v.as_str()) {
                    // format: "AS15169 Google LLC"
                    if let Some(num) = as_str.split_whitespace().next() {
                        found = num.trim_start_matches("AS").to_string();
                    }
                }
            }
        }
        if found.is_empty() { println!("  [!] could not resolve target to an ASN."); return Ok(()); }
        row("Resolved ASN", &format!("AS{}", found));
        found
    };

    let sp = spinner("querying BGP data...");

    // RIPEstat — free, no key, returns announced prefixes + holder
    let overview_url = format!("https://stat.ripe.net/data/as-overview/data.json?resource=AS{}", asn_number);
    if let Some(res) = get_with_retry(&client, &overview_url, cfg.max_retries).await {
        if let Ok(j) = res.json::<Value>().await {
            sp.finish_and_clear();
            if let Some(data) = j.get("data") {
                section(&format!("AS{} overview", asn_number));
                if let Some(holder) = data.get("holder").and_then(|v| v.as_str()) { row("Holder", holder); }
                if let Some(announced) = data.get("announced").and_then(|v| v.as_bool()) {
                    row("Announced", if announced { "yes" } else { "no" });
                }
                if let Some(block) = data.get("block") {
                    if let Some(desc) = block.get("desc").and_then(|v| v.as_str()) { row("Block", desc); }
                    if let Some(name) = block.get("name").and_then(|v| v.as_str()) { row("Registry", name); }
                }
            }
        }
    } else {
        sp.finish_and_clear();
    }

    sleep(Duration::from_millis(200)).await;

    // Announced prefixes
    let prefixes_url = format!("https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS{}", asn_number);
    if let Some(res) = get_with_retry(&client, &prefixes_url, cfg.max_retries).await {
        if let Ok(j) = res.json::<Value>().await {
            if let Some(prefixes) = j.get("data").and_then(|d| d.get("prefixes")).and_then(|p| p.as_array()) {
                section(&format!("announced prefixes ({})", prefixes.len()));
                let mut v4 = 0;
                let mut v6 = 0;
                for p in prefixes.iter().take(60) {
                    if let Some(prefix) = p["prefix"].as_str() {
                        if prefix.contains(':') { v6 += 1; } else { v4 += 1; }
                        println!("  {} {}", "↳".magenta(), prefix.cyan());
                    }
                }
                if prefixes.len() > 60 {
                    println!("  {} {} more prefixes...", "…".dimmed(), prefixes.len() - 60);
                }
                println!("\n  {} IPv4 prefixes: {}  |  IPv6 prefixes: {}", "⊕".green(), v4, v6);
            }
        }
    }
    Ok(())
}

// ═══════════════════════════════════════════════════════════════════════════════
// MODULE: META — document metadata extraction (NEW)
// ═══════════════════════════════════════════════════════════════════════════════

async fn meta_mode(cfg: &Config, path: &str) -> Result<(), Box<dyn Error>> {
    section(&format!("document metadata: {}", path.yellow().bold()));
    let data = match load_bytes(cfg, path).await {
        Ok(d) => d,
        Err(e) => { println!("  [!] {}", e); return Ok(()); }
    };

    row("Size", &format!("{} bytes", data.len()));
    let kind = detect_filetype(&data);
    row("Type", kind);

    match kind {
        "PDF" => extract_pdf_meta(&data),
        "DOCX/ZIP" => extract_docx_meta(&data),
        "JPEG" | "TIFF" => print_exif(&data),
        "PNG" => extract_png_meta(&data),
        _ => println!("  {}", "no metadata extractor for this type — showing EXIF attempt.".dimmed()),
    }
    Ok(())
}

fn detect_filetype(data: &[u8]) -> &'static str {
    if data.len() < 8 { return "unknown"; }
    if data.starts_with(b"%PDF") { return "PDF"; }
    if data.starts_with(b"PK") { return "DOCX/ZIP"; }
    if data.starts_with(&[0xFF, 0xD8, 0xFF]) { return "JPEG"; }
    if data.starts_with(&[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]) { return "PNG"; }
    if data.starts_with(b"II*\0") || data.starts_with(b"MM\0*") { return "TIFF"; }
    "unknown"
}

// PDF metadata — scan for /Author /Creator /Producer /CreationDate in the raw bytes.
// Lightweight, no pdf parsing dependency needed.
fn extract_pdf_meta(data: &[u8]) {
    section("pdf metadata");
    let text = String::from_utf8_lossy(data);
    let fields = ["Author","Creator","Producer","Title","Subject","Keywords","CreationDate","ModDate"];
    let mut found_any = false;
    for field in &fields {
        let needle = format!("/{}", field);
        if let Some(pos) = text.find(&needle) {
            let after = &text[pos + needle.len()..];
            // value is usually in (parentheses) or <hex>
            if let Some(start) = after.find('(') {
                if let Some(end) = after[start+1..].find(')') {
                    let val = &after[start+1..start+1+end];
                    if !val.is_empty() && val.len() < 200 {
                        row(field, val);
                        found_any = true;
                    }
                }
            }
        }
    }
    if !found_any { println!("  {}", "no embedded metadata found in PDF.".yellow()); }
    println!("\n  {} {}", "↳".magenta(), "author/producer fields often reveal real names & software versions".dimmed());
}

// DOCX = zip; core.xml inside holds author/company. Scan raw bytes for the xml tags
// after a cheap check — full unzip would need a zip crate; we surface what's visible.
fn extract_docx_meta(data: &[u8]) {
    section("docx/office metadata");
    let text = String::from_utf8_lossy(data);
    let tags = [
        ("dc:creator", "Author"),
        ("cp:lastModifiedBy", "Last Modified By"),
        ("Company", "Company"),
        ("dc:title", "Title"),
        ("dcterms:created", "Created"),
        ("dcterms:modified", "Modified"),
        ("Application", "Application"),
    ];
    let mut found_any = false;
    for (tag, label) in &tags {
        let open = format!("<{}>", tag);
        let close = format!("</{}>", tag);
        if let Some(s) = text.find(&open) {
            if let Some(e) = text[s+open.len()..].find(&close) {
                let val = &text[s+open.len()..s+open.len()+e];
                if !val.is_empty() && val.len() < 200 {
                    row(label, val);
                    found_any = true;
                }
            }
        }
    }
    if !found_any {
        println!("  {}", "metadata is zip-compressed — unzip docProps/core.xml for full data.".yellow());
        println!("  {} {}", "↳".magenta(), "tip: unzip -p file.docx docProps/core.xml".dimmed());
    }
}

fn extract_png_meta(data: &[u8]) {
    section("png metadata");
    let text = String::from_utf8_lossy(data);
    // PNG tEXt/iTXt chunks hold key=value pairs (Software, Author, Comment, etc.)
    let keys = ["Software","Author","Comment","Description","Copyright","Creation Time","Source"];
    let mut found_any = false;
    for key in &keys {
        if let Some(pos) = text.find(key) {
            let after = &text[pos + key.len()..];
            let val: String = after.chars().skip(1).take_while(|c| *c != '\0' && (c.is_ascii_graphic() || *c == ' ')).collect();
            if !val.is_empty() && val.len() < 200 {
                row(key, val.trim());
                found_any = true;
            }
        }
    }
    if !found_any { println!("  {}", "no text chunks found in PNG.".yellow()); }
}

// ═══════════════════════════════════════════════════════════════════════════════
// MODULE: PERMUTE — username variations, then scan each across networks
// ═══════════════════════════════════════════════════════════════════════════════

// Generate common username variations from a base handle.
// e.g. "john doe" / "johndoe" -> john.doe, john_doe, j.doe, johnd, john-doe, ...
fn permute_username(base: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let cleaned = base.trim().to_lowercase();

    // split on common separators to detect first/last parts
    let parts: Vec<String> = cleaned
        .split(|c: char| c == ' ' || c == '.' || c == '_' || c == '-')
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .collect();

    // always include the raw (despaced) form
    let joined: String = parts.concat();
    if !joined.is_empty() { out.push(joined.clone()); }

    if parts.len() >= 2 {
        let first = &parts[0];
        let last = &parts[parts.len() - 1];
        let fi = first.chars().next().unwrap_or(' ');
        let li = last.chars().next().unwrap_or(' ');
        let seps = [".", "_", "-", ""];
        for s in &seps {
            out.push(format!("{}{}{}", first, s, last));        // john.doe
            out.push(format!("{}{}{}", fi, s, last));           // j.doe
            out.push(format!("{}{}{}", first, s, li));          // john.d
        }
        out.push(format!("{}{}", last, first));                 // doejohn
        out.push(format!("{}{}", first, last.chars().next().unwrap_or(' '))); // johnd
    }

    // numeric suffixes people love
    let suffixes = ["", "1", "01", "123", "07", "2024", "_", "x", "xx", "official", "real"];
    let mut expanded: Vec<String> = Vec::new();
    for u in &out {
        for suf in &suffixes {
            expanded.push(format!("{}{}", u, suf));
        }
    }

    // dedup, drop too-short, cap the list so we don't hammer 200 requests
    let mut seen = HashSet::new();
    let mut final_list: Vec<String> = Vec::new();
    for u in expanded {
        if u.len() >= 3 && seen.insert(u.clone()) {
            final_list.push(u);
        }
        if final_list.len() >= 40 { break; }
    }
    final_list
}

async fn permute_mode(cfg: &Config, base: &str) -> Result<(), Box<dyn Error>> {
    section(&format!("username permutator: {}", base.yellow().bold()));

    let variations = permute_username(base);
    println!("  generated {} variations:\n", variations.len().to_string().cyan().bold());
    for v in &variations {
        println!("  {} {}", "·".magenta(), v.dimmed());
    }

    // Lightweight presence check on a few high-signal networks, in parallel.
    // (We don't run the full 61-site scan x40 names — that's too many requests.)
    let probes: &[(&str, &str)] = &[
        ("GitHub",    "https://github.com/{}"),
        ("Reddit",    "https://www.reddit.com/user/{}"),
        ("Instagram", "https://www.instagram.com/{}/"),
        ("Telegram",  "https://t.me/{}"),
        ("Twitter",   "https://twitter.com/{}"),
    ];

    section("quick presence check on key networks");
    let client = cfg.build_client()?;
    let total = (variations.len() * probes.len()) as u64;
    let pb = ProgressBar::new(total);
    pb.set_style(bar_style());
    pb.set_message("probing...");

    let hits: Arc<Mutex<Vec<(String, String, String)>>> = Arc::new(Mutex::new(vec![]));
    let start = Instant::now();
    let mut tasks = vec![];

    for v in &variations {
        for (net, tmpl) in probes {
            let c = client.clone();
            let url = tmpl.replace("{}", v);
            let net = net.to_string();
            let vc = v.clone();
            let h = Arc::clone(&hits);
            let pb2 = pb.clone();
            tasks.push(tokio::spawn(async move {
                if let Ok(resp) = c.get(&url).send().await {
                    if resp.status() == StatusCode::OK {
                        h.lock().unwrap().push((vc, net, url));
                    }
                }
                pb2.inc(1);
            }));
        }
    }
    join_all(tasks).await;
    pb.finish_and_clear();

    let mut locked = hits.lock().unwrap();
    locked.sort_by(|a, b| a.0.cmp(&b.0).then(a.1.cmp(&b.1)));
    println!();
    if locked.is_empty() {
        println!("  {} no hits on probed networks (try the full `username` scan)", "–".dimmed());
    } else {
        println!("  [{}] {} possible hits:\n", "+".green().bold(), locked.len().to_string().green().bold());
        for (v, net, url) in locked.iter() {
            println!("  {} {:<18} {:<10} {}", "●".green(), v.bold(), net.cyan(), url.dimmed());
        }
        println!("\n  {} {}", "note:".yellow(),
                 "status 200 != confirmed account on every site — verify manually".dimmed());
    }
    println!("\n  {} probed in {:.2}s", "✓".green(), start.elapsed().as_secs_f64());
    Ok(())
}

// ═══════════════════════════════════════════════════════════════════════════════
// MODULE: DORKS — generate Google/Bing dork links for a target
// ═══════════════════════════════════════════════════════════════════════════════

async fn dorks_mode(_cfg: &Config, target: &str) -> Result<(), Box<dyn Error>> {
    section(&format!("dork generator: {}", target.yellow().bold()));
    let t = strip_proto(target);
    let enc = urlencoding::encode(&t);

    // (label, raw dork query)
    let dorks: &[(&str, String)] = &[
        ("exposed directories",   format!("site:{} intitle:index.of", t)),
        ("config & env files",    format!("site:{} ext:env | ext:cfg | ext:conf | ext:ini", t)),
        ("sql dumps",             format!("site:{} ext:sql | ext:dbf | ext:mdb", t)),
        ("log files",             format!("site:{} ext:log", t)),
        ("backup files",          format!("site:{} ext:bak | ext:old | ext:backup", t)),
        ("documents",             format!("site:{} ext:pdf | ext:doc | ext:docx | ext:xls", t)),
        ("login pages",           format!("site:{} inurl:login | inurl:signin | inurl:admin", t)),
        ("api keys & secrets",    format!("site:{} intext:\"api_key\" | intext:\"apikey\" | intext:\"secret\"", t)),
        ("passwords in text",     format!("site:{} intext:password filetype:txt", t)),
        ("git exposure",          format!("site:{} inurl:.git", t)),
        ("open redirects",        format!("site:{} inurl:redirect | inurl:url=", t)),
        ("subdomains via google", format!("site:*.{} -www", t)),
        ("emails on site",        format!("site:{} intext:\"@{}\"", t, t)),
        ("php errors",            format!("site:{} \"PHP Parse error\" | \"PHP Warning\" | \"PHP Error\"", t)),
        ("wordpress paths",       format!("site:{} inurl:wp-content | inurl:wp-admin", t)),
    ];

    section("google dorks");
    for (label, q) in dorks {
        let url = format!("https://www.google.com/search?q={}", urlencoding::encode(q));
        println!("  {} {}", "▸".magenta(), label.bold());
        println!("    {} {}", "query:".dimmed(), q);
        println!("    {}", url.cyan());
        println!();
    }

    section("other engines (same target)");
    println!("  {} Bing:       https://www.bing.com/search?q=site%3A{}", "→".cyan(), enc);
    println!("  {} DuckDuckGo: https://duckduckgo.com/?q=site%3A{}", "→".cyan(), enc);
    println!("  {} Yandex:     https://yandex.com/search/?text=site%3A{}", "→".cyan(), enc);
    println!("  {} Shodan:     https://www.shodan.io/search?query=hostname%3A{}", "→".cyan(), enc);
    println!("  {} Censys:     https://search.censys.io/search?resource=hosts&q={}", "→".cyan(), enc);
    println!("\n  {} {}", "tip:".yellow(), "for OSINT use a logged-out browser or VPN to avoid skewed/personalized results".dimmed());
    Ok(())
}

// ═══════════════════════════════════════════════════════════════════════════════
// MODULE: FAVICON — hash a site's favicon for Shodan/FOFA pivoting
// ═══════════════════════════════════════════════════════════════════════════════

async fn favicon_mode(cfg: &Config, target: &str) -> Result<(), Box<dyn Error>> {
    section(&format!("favicon hash: {}", target.yellow().bold()));

    let mut base = target.to_string();
    if !base.starts_with("http") { base = format!("https://{}", base); }
    let host = strip_proto(target);

    let client = cfg.build_client()?;
    let sp = spinner("fetching favicon...");

    // Try the well-known default location first, then parse HTML for a <link rel="icon">.
    let mut favicon_bytes: Option<Vec<u8>> = None;
    let mut favicon_url = format!("{}/favicon.ico", base.trim_end_matches('/'));

    if let Ok(res) = client.get(&favicon_url).send().await {
        if res.status().is_success() {
            if let Ok(b) = res.bytes().await {
                if !b.is_empty() { favicon_bytes = Some(b.to_vec()); }
            }
        }
    }

    // Fallback: scrape <link rel="icon"> from the homepage
    if favicon_bytes.is_none() {
        if let Ok(res) = client.get(&base).send().await {
            if let Ok(body) = res.text().await {
                let doc = Html::parse_document(&body);
                if let Ok(sel) = Selector::parse(r#"link[rel~="icon"]"#) {
                    if let Some(el) = doc.select(&sel).next() {
                        if let Some(href) = el.value().attr("href") {
                            let resolved = if href.starts_with("http") {
                                href.to_string()
                            } else if let Some(stripped) = href.strip_prefix("//") {
                                format!("https://{}", stripped)
                            } else if href.starts_with('/') {
                                format!("{}{}", base.trim_end_matches('/'), href)
                            } else {
                                format!("{}/{}", base.trim_end_matches('/'), href)
                            };
                            favicon_url = resolved.clone();
                            if let Ok(r2) = client.get(&resolved).send().await {
                                if let Ok(b) = r2.bytes().await {
                                    if !b.is_empty() { favicon_bytes = Some(b.to_vec()); }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    sp.finish_and_clear();

    match favicon_bytes {
        Some(bytes) => {
            row("Favicon URL", &favicon_url);
            row("Size", &format!("{} bytes", bytes.len()));

            // Shodan's http.favicon.hash is MurmurHash3 (32-bit signed) over the
            // standard-base64 of the icon, encoded in 76-char lines with trailing newline.
            let b64 = base64_mime_encode(&bytes);
            let mmh3 = murmur3_32(b64.as_bytes(), 0) as i32;
            // md5 is handy for FOFA/quick dedup
            let md5sum = format!("{:x}", md5::compute(&bytes));

            section("hashes");
            row("MurmurHash3 (Shodan)", &mmh3.to_string().green().bold().to_string());
            row("MD5", &md5sum);

            section("pivot — find hosts with the same favicon");
            println!("  {} Shodan: https://www.shodan.io/search?query=http.favicon.hash%3A{}", "→".cyan(), mmh3);
            println!("  {} FOFA:   https://fofa.info/result?qbase64={}",
                     "→".cyan(), urlencoding::encode(&general_base64(format!("icon_hash=\"{}\"", mmh3).as_bytes())));
            println!("  {} ZoomEye: https://www.zoomeye.org/searchResult?q=iconhash%3A%22{}%22", "→".cyan(), md5sum);
            println!("\n  {} {}", "why:".yellow(),
                     "same favicon across IPs often reveals the real server behind a CDN or related infra".dimmed());
        }
        None => {
            println!("  {} no favicon found at {} or in homepage HTML", "–".dimmed(), host);
        }
    }
    Ok(())
}

// MurmurHash3 x86_32 — matches Shodan's favicon hashing.
fn murmur3_32(data: &[u8], seed: u32) -> u32 {
    let c1: u32 = 0xcc9e_2d51;
    let c2: u32 = 0x1b87_3593;
    let mut h1 = seed;
    let nblocks = data.len() / 4;

    for i in 0..nblocks {
        let i4 = i * 4;
        let mut k1 = (data[i4] as u32)
            | ((data[i4 + 1] as u32) << 8)
            | ((data[i4 + 2] as u32) << 16)
            | ((data[i4 + 3] as u32) << 24);
        k1 = k1.wrapping_mul(c1);
        k1 = k1.rotate_left(15);
        k1 = k1.wrapping_mul(c2);
        h1 ^= k1;
        h1 = h1.rotate_left(13);
        h1 = h1.wrapping_mul(5).wrapping_add(0xe654_6b64);
    }

    let tail = &data[nblocks * 4..];
    let mut k1: u32 = 0;
    if tail.len() >= 3 { k1 ^= (tail[2] as u32) << 16; }
    if tail.len() >= 2 { k1 ^= (tail[1] as u32) << 8; }
    if !tail.is_empty() {
        k1 ^= tail[0] as u32;
        k1 = k1.wrapping_mul(c1);
        k1 = k1.rotate_left(15);
        k1 = k1.wrapping_mul(c2);
        h1 ^= k1;
    }

    h1 ^= data.len() as u32;
    h1 ^= h1 >> 16;
    h1 = h1.wrapping_mul(0x85eb_ca6b);
    h1 ^= h1 >> 13;
    h1 = h1.wrapping_mul(0xc2b2_ae35);
    h1 ^= h1 >> 16;
    h1
}

// Standard base64 (used inside FOFA query building).
fn general_base64(data: &[u8]) -> String {
    const T: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in data.chunks(3) {
        let b = [chunk[0], *chunk.get(1).unwrap_or(&0), *chunk.get(2).unwrap_or(&0)];
        out.push(T[(b[0] >> 2) as usize] as char);
        out.push(T[(((b[0] & 0x03) << 4) | (b[1] >> 4)) as usize] as char);
        if chunk.len() > 1 { out.push(T[(((b[1] & 0x0f) << 2) | (b[2] >> 6)) as usize] as char); }
        else { out.push('='); }
        if chunk.len() > 2 { out.push(T[(b[2] & 0x3f) as usize] as char); }
        else { out.push('='); }
    }
    out
}

// MIME base64: standard base64 split into 76-char lines, each line + "\n".
// This is what python's base64.encodebytes produces, which Shodan's hashing expects.
fn base64_mime_encode(data: &[u8]) -> String {
    let raw = general_base64(data);
    let mut out = String::new();
    let bytes = raw.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let end = (i + 76).min(bytes.len());
        out.push_str(std::str::from_utf8(&bytes[i..end]).unwrap_or(""));
        out.push('\n');
        i = end;
    }
    out
}

// ═══════════════════════════════════════════════════════════════════════════════
// MODULE: FULL RECON CHAIN
// ═══════════════════════════════════════════════════════════════════════════════

async fn recon_mode(cfg: &Config, target: &str) -> Result<(), Box<dyn Error>> {
    println!("\n{}", "━".repeat(60).magenta().bold());
    println!("  {} FULL RECON: {}", "▶▶".magenta().bold(), target.yellow().bold());
    println!("{}", "━".repeat(60).magenta().bold());
    println!("  {}", "running: ip → dns → whois → crt → tls → headers → reverseip → ports".dimmed());

    let start = Instant::now();
    let clean = strip_proto(target);
    let is_ip = clean.parse::<IpAddr>().is_ok();

    ip_lookup_mode(cfg, &clean).await?;
    sleep(Duration::from_millis(400)).await;
    dns_mode(cfg, &clean).await?;
    sleep(Duration::from_millis(400)).await;

    if !is_ip {
        whois_mode(cfg, &clean).await?;
        sleep(Duration::from_millis(400)).await;
        crt_mode(cfg, &clean).await?;
        sleep(Duration::from_millis(400)).await;
        tls_mode(cfg, &clean).await?;
        sleep(Duration::from_millis(400)).await;
        headers_mode(cfg, &clean).await?;
        sleep(Duration::from_millis(400)).await;
    }

    reverse_ip_mode(cfg, &clean).await?;
    sleep(Duration::from_millis(400)).await;
    port_scan_mode(&clean, "common").await?;

    println!("\n{}", "━".repeat(60).magenta().bold());
    println!("  {} full recon done in {:.2}s", "✓".green().bold(), start.elapsed().as_secs_f64());
    println!("{}", "━".repeat(60).magenta().bold());
    Ok(())
}

