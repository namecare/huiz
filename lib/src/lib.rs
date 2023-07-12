pub mod strings_to_hide;
pub mod legacy;
pub mod data;
pub mod utils;
pub mod error;

use std::net::{TcpStream, ToSocketAddrs};
use std::io::{BufRead, BufReader, BufWriter, Error, Write};
use std::process::abort;
use std::time::Duration;
use std::str::from_utf8;
use idna::domain_to_ascii;
use crate::data::{ANICHOST, DEFAULT_PORT, DENICHOST, DKNICHOST, QNICHOST_TAIL, RNICHOST, VNICHOST, WHOIS_REFERRAL, WHOIS_WHERE};

use crate::strings_to_hide::HIDE_STRINGS;
use crate::utils::is_host_char;

const HIDE_NOT_STARTED: i32 = -1;
const HIDE_DISABLED: i32 = -2;
const HIDE_TO_THE_END: i32 = -3;

#[derive(Debug, Clone)]
pub struct Whois {
    pub raw: String
}



pub fn hide_line(hide: &mut i32, line: &str) -> bool {
    let hide_strings = HIDE_STRINGS;
    let mut i = 0;

    match *hide {
        HIDE_TO_THE_END => true,
        HIDE_DISABLED => false,
        HIDE_NOT_STARTED => {
            while let Some(hide_str) = hide_strings[i] {
                if line.starts_with(hide_str) {
                    *hide = if hide_strings[i + 1].is_none() {
                        HIDE_TO_THE_END
                    } else {
                        i.try_into().unwrap()
                    };

                     return true
                }

                i += 2;
            }

            false
        }
        _ if *hide > HIDE_NOT_STARTED => {
            let idx: usize = (*hide).try_into().expect("Expect usize");

            if hide_strings[idx + 1] == Some("") {
                if line.is_empty() {
                    *hide = HIDE_NOT_STARTED;
                    return false
                }
            } else if let Some(hide_str) = hide_strings[idx + 1] {
                if line.starts_with(hide_str) {
                    *hide = HIDE_NOT_STARTED;
                    return true
                }
            }
            return true
        }
        _ => false
    }
}

fn prepare_query(query: &str, flags: u8, hostname: &str) -> String {
    let should_spam_me = flags & WHOIS_SPAM_ME != 0;

    if !should_spam_me && (hostname.eq_ignore_ascii_case(DENICHOST) ||
        hostname.eq_ignore_ascii_case(format!("de{:?}", QNICHOST_TAIL).as_str())) {
        let idn = query.chars().any(|c| !c.is_ascii());
        let dn_arg = if idn { "" } else { ",ace" };
        format!("-T dn{} {}", dn_arg, query)
    } else if !should_spam_me && (hostname.eq_ignore_ascii_case(DKNICHOST) ||
        hostname.eq_ignore_ascii_case(format!("dk{:?}", QNICHOST_TAIL).as_str())) {
        format!("--show-handles {}", query)
    } else if should_spam_me || query.contains(' ') {
        format!("{}", query)
    } else if hostname.eq_ignore_ascii_case(ANICHOST) {
        if query.starts_with("AS") && query[2..].chars().all(|c| c.is_ascii_digit()) {
            format!("+ a {}", &query[2..])
        } else {
            format!("+ {}", query)
        }
    } else if hostname.eq_ignore_ascii_case(VNICHOST) {
        format!("domain {}", query)
    } else if hostname.eq_ignore_ascii_case("whois.nic.ad.jp") ||
        hostname.eq_ignore_ascii_case("whois.nic.ad.jp") {
        format!("{}/e", query)
    } else {
        format!("{}", query)
    }
}

fn do_query(mut stream: &TcpStream, query: &str, hide_discl: i32) -> Result<Option<String>, Box<dyn std::error::Error>> {
    let mut buf = vec![0u8; 2000];
    let mut referral_server = None;
    let mut hide = hide_discl;

    let mut temp = query.to_string();
    temp.push_str("\r\n");

    stream.write_all(temp.as_bytes())?;

    let mut reader = BufReader::new(stream);

    while reader.read_until(b'\n', &mut buf).unwrap_or(0) > 0 {
        let mut line = from_utf8(&buf)?.trim().to_string();

        if referral_server.is_none() {
            if line.contains("referto:") {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 4 {
                    referral_server = Some(format!("{}:{}", parts[1], parts[2]));
                }
            } else if line.starts_with("ReferralServer:") {
                if let Some(idx) = line.find("rwhois://") {
                    referral_server = Some(line[idx+9..].to_string());
                } else if let Some(idx) = line.find("whois://") {
                    referral_server = Some(line[idx+8..].to_string());
                }
                if let Some(ref mut server) = referral_server {
                    if let Some(idx) = server.find(|c| c == '/' || c == '\r' || c == '\n') {
                        server.truncate(idx);
                    }
                }
            }
        }

        if hide_line(&mut hide, &line) {
            continue;
        }

        println!("{}", line);
        buf.clear();
    }

    if hide > HIDE_NOT_STARTED && hide != HIDE_TO_THE_END {
        return Err(Box::new(std::io::Error::new(std::io::ErrorKind::Other,
                                                "Catastrophic error: disclaimer text has been changed.\nPlease upgrade this program.\n")));
    }

    Ok(referral_server)
}

fn query_iana(mut stream: &TcpStream, query: &str) -> Result<Option<String>, Box<dyn std::error::Error>> {
    let mut buf = vec![0u8; 2000];
    let mut referral_server = None;

    let mut temp = query.to_string();
    temp.push_str("\r\n");

    stream.write_all(temp.as_bytes())?;

    let mut reader = BufReader::new(stream);

    while reader.read_until(b'\n', &mut buf)? > 0 {
        let mut line = from_utf8(&buf)?.trim().to_string();

        if referral_server.is_none() && line.starts_with("refer:") {
            let server = line.splitn(2, ":").nth(1).unwrap_or("").trim();
            referral_server = Some(server.to_string());
        }

        println!("{}", line);
        buf.clear();
    }

    Ok(referral_server)
}

pub const WHOIS_RECURSE: u8 = 0x01;
pub const WHOIS_QUICK: u8 = 0x02;
pub const WHOIS_SPAM_ME: u8 = 0x04;

fn choose_server(domain: &str) -> &str {
    for server in WHOIS_WHERE {
        let suffix_len = server.suffix.len();
        if domain.len() > suffix_len && domain.ends_with(&server.suffix) {
            return server.server;
        }
    }
    panic!("No default whois server");
}

fn open_conn(server: &str, port: &str) -> Result<TcpStream, Error> {
    let addr = format!("{}:{}", server, port);
    let addrs = addr.to_socket_addrs()?;

    let mut stream = None;

    for a in addrs {
        match TcpStream::connect_timeout(&a, Duration::from_secs(60)) {
            Ok(s) => {
                stream = Some(s);
                break;
            }
            Err(_) => continue,
        };
    }

    match stream {
        Some(s) => Ok(s),
        None => Err(Error::new(
            std::io::ErrorKind::Other,
            format!("Failed to connect to {}", server),
        )),
    }
}

pub fn whois(query: &str, hostname: &str, hostport: &str, flags: u8) -> Result<(), Error> {
    let hostres = hostname;
    let stream = open_conn(hostres, hostport)?;

    let mut reader = BufReader::new(&stream);
    let mut writer = BufWriter::new(&stream);

    let mut nhost: Option<String> = None;
    let mut nport: Option<String> = None;

    let should_recurse = flags & WHOIS_RECURSE != 0;
    let should_spam_me = flags & WHOIS_SPAM_ME != 0;

    let mut prepared_query = prepare_query(query, flags, hostname);
    prepared_query.push_str("\n");
    writer.write_all(prepared_query.as_bytes());
    writer.flush();

    let mut comment = 0;
    let mut hide_state = HIDE_NOT_STARTED;

    if !should_spam_me && (hostname.eq_ignore_ascii_case(ANICHOST) || hostname.eq_ignore_ascii_case(RNICHOST)) {
        comment = 2;
    }

    let mut buf = Vec::new();
    loop {
        buf.clear();
        match reader.read_until(b'\n', &mut buf) {
            Ok(0) => break,
            Ok(_) => {
                let line = std::str::from_utf8(&buf).expect("Expect line");

                if !should_spam_me && line.len() == 5 && line == "-- \r\n" {
                    break;
                }

                if comment == 1 && line.starts_with("#") {
                    break;
                } else if comment == 2 {
                    let p = &line[0..1];
                    if "#%\r\n".find(p).is_some() {
                        continue;
                    }else{
                        comment = 1;
                    }
                }

                if !hide_line(&mut hide_state, line) {
                    print!("{}", line);
                }

                if should_recurse && nhost.is_none() {
                    for referral in WHOIS_REFERRAL {
                        if let Some(pos) = line.find(referral.prefix) {
                            let mut p = line[pos + referral.len..].trim_start().chars();
                            let host = p.by_ref().take_while(|c| is_host_char(*c)).collect::<String>();
                            if !host.is_empty() {
                                if p.next() == Some(':') {
                                    let pstr = p.as_str();
                                    let port = pstr.chars().take_while(|c| c.is_ascii_digit()).collect::<String>();
                                    if !port.is_empty() {
                                        nhost = Some(host);
                                        nport = Some(port);
                                        break;
                                    }
                                }
                                nhost = Some(host);
                                break;
                            }
                        }
                    }

                    for arin in &["netname:        ERX-NETBLOCK\n", "netname:        NON-RIPE-NCC-MANAGED-ADDRESS-BLOCK\n"] {
                        if line == *arin {
                            nhost = Some(ANICHOST.to_owned());
                            nport = Some(DEFAULT_PORT.to_owned());
                            break;
                        }
                    }
                }
            }
            Err(err) => {
                println!("{:?}", err);
                return Err(err)
            }
        }
    }

    drop(writer);
    drop(reader);

    if let Some(nhost) = nhost {
        let nport = nport.unwrap_or(String::from("43"));

        if hostname.ne(&nhost) {
            println!("# {}\n", nhost);
            whois(query, &nhost, &nport, flags)?;
        }
    }

    Ok(())
}



#[cfg(test)]
mod tests {
    use super::*;
    use super::utils::*;

    #[test]
    fn whois_test() {
        std::env::set_var("RUST_LOG", "debug");
        let domain = normalize_domain("club.dk").expect("Expect Domain");
        let r = whois(domain.as_str(),
                                     "whois.iana.org",
                                     "43",
                                     WHOIS_RECURSE);
    }
}
