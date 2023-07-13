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
use crate::data::{ANICHOST, DEFAULT_PORT, DENICHOST, DKNICHOST, IANAHOST, QNICHOST_TAIL, RNICHOST, VNICHOST, WHOIS_REFERRAL, WHOIS_WHERE};

use crate::strings_to_hide::HIDE_STRINGS;
use crate::utils::is_host_char;

const HIDE_NOT_STARTED: i32 = -1;
const HIDE_DISABLED: i32 = -2;
const HIDE_TO_THE_END: i32 = -3;

pub const WHOIS_RECURSE: u8 = 0x01;
pub const WHOIS_QUICK: u8 = 0x02;
pub const WHOIS_SPAM_ME: u8 = 0x04;

#[derive(Debug, Clone)]
pub struct WhoisResult {
    pub chain: Vec<Whois>
}

#[derive(Debug, Clone)]
pub struct Whois {
    pub referral: Option<String>,
    pub referral_port: Option<String>,
    pub raw: String
}

pub fn whois(q: &str) -> Result<WhoisResult, Box<dyn std::error::Error>> {
    let host = choose_server(q);
    let port = DEFAULT_PORT;
    query(q, host, port, WHOIS_RECURSE | WHOIS_SPAM_ME)
}

fn query(query: &str, host: &str, port: &str, flags: u8) -> Result<WhoisResult, Box<dyn std::error::Error>> {
    let stream = open_conn(host, port)?;
    let prepared_query = prepare_query(query, flags, host);
    let whois = do_query(&stream, &prepared_query, flags)?;

    let r = WhoisResult {
        chain: vec![whois]
    };

    Ok(r)
}

fn do_query(mut stream: &TcpStream, query: &str, flags: u8) -> Result<Whois, Error> {
    let mut reader = BufReader::new(stream);
    let mut writer = BufWriter::new(stream);

    let mut nhost: Option<String> = None;
    let mut nport: Option<String> = None;

    let should_spam_me = flags & WHOIS_SPAM_ME != 0;

    writer.write_all(query.as_bytes())?;
    writer.flush()?;

    let mut hide_state = HIDE_NOT_STARTED;

    let mut buf = Vec::new();
    loop {
        match reader.read_until(b'\n', &mut buf) {
            Ok(0) => break,
            Ok(_) => {
                let line = from_utf8(&buf).expect("Expect line");

                if !should_spam_me && hide_line(&mut hide_state, line) {
                    print!("{}", line);
                }

                if nhost.is_none() {
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

    let raw = from_utf8(&buf).expect("Expect raw");

    let whois = Whois {
        referral: nhost,
        referral_port: nport,
        raw: raw.to_string(),
    };

    Ok(whois)
}

fn choose_server(domain: &str) -> &str {
    for server in WHOIS_WHERE {
        let suffix_len = server.suffix.len();
        if domain.len() > suffix_len && domain.ends_with(&server.suffix) {
            return server.server;
        }
    }

    IANAHOST
}

fn prepare_query(query: &str, flags: u8, hostname: &str) -> String {
    let should_spam_me = flags & WHOIS_SPAM_ME != 0;
    let mut builded_query: String;

    if !should_spam_me && (hostname.eq_ignore_ascii_case(DENICHOST) ||
        hostname.eq_ignore_ascii_case(format!("de{:?}", QNICHOST_TAIL).as_str())) {
        let idn = query.chars().any(|c| !c.is_ascii());
        let dn_arg = if idn { "" } else { ",ace" };
        builded_query = format!("-T dn{} {}", dn_arg, query);
    } else if !should_spam_me && (hostname.eq_ignore_ascii_case(DKNICHOST) ||
        hostname.eq_ignore_ascii_case(format!("dk{:?}", QNICHOST_TAIL).as_str())) {
        builded_query = format!("--show-handles {}", query);
    } else if should_spam_me || query.contains(' ') {
        builded_query = format!("{}", query);
    } else if hostname.eq_ignore_ascii_case(ANICHOST) {
        if query.starts_with("AS") && query[2..].chars().all(|c| c.is_ascii_digit()) {
            builded_query = format!("+ a {}", &query[2..]);
        } else {
            builded_query = format!("+ {}", query);
        }
    } else if hostname.eq_ignore_ascii_case(VNICHOST) {
        builded_query = format!("domain {}", query);
    } else if hostname.eq_ignore_ascii_case("whois.nic.ad.jp") ||
        hostname.eq_ignore_ascii_case("whois.nic.ad.jp") {
        builded_query = format!("{}/e", query)
    } else {
        builded_query = format!("{}", query)
    };

    builded_query.push_str("\n");
    builded_query
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

fn hide_line(hide: &mut i32, line: &str) -> bool {
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

#[cfg(test)]
mod tests {
    use super::*;
    use super::utils::*;

    #[test]
    fn whois_test() {
        let domain = "google.com";
        let r = whois(domain);
        println!("{:?}", r)
    }
}
