mod strings_to_hide;
mod whois_freebsd;

use std::net::{TcpStream, ToSocketAddrs};
use std::io::{BufRead, BufReader, BufWriter, Error, Write};
use std::process::abort;
use std::time::Duration;
use std::str::from_utf8;
use idna::domain_to_ascii;

use crate::strings_to_hide::HIDE_STRINGS;

const HIDE_NOT_STARTED: i32 = -1;
const HIDE_DISABLED: i32 = -2;
const HIDE_TO_THE_END: i32 = -3;

fn normalize_domain(dom: &str) -> String {
    let mut ret = dom.to_string();
    ret = ret.trim_end_matches(|c: char| c == '.' || c.is_whitespace()).to_string();

    // find the start of the last word if there are spaces in the query
    let domain_start = if ret.contains(' ') {
        ret.rsplitn(2, ' ').next().unwrap()
    } else {
        &ret
    };

    match domain_to_ascii(domain_start) {
        Ok(puny) => {
            if ret != domain_start {
                let prefix_len = ret.len() - domain_start.len();
                format!("{}{}", &ret[..prefix_len], puny)
            } else {
                puny
            }
        }
        Err(_) => ret
    }
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

fn query_crsnic(mut stream: &TcpStream, query: &str) -> Option<String> {
    let mut buf = Vec::new();
    let mut temp = String::new();
    let mut hide: i32 = HIDE_NOT_STARTED;
    let mut referral_server: Option<String> = None;
    let mut state = 0;
    let dotscount = query.matches('.').count();

    if dotscount == 1 && !query.contains(&['=', '~', ' '][..]) {
        temp.push_str("domain ");
    }
    temp.push_str(query);
    temp.push_str("\r\n");
    stream.write_all(temp.as_bytes()).expect("Expect written");

    let mut reader = BufReader::new(stream);
    while reader.read_until(b'\n', &mut buf).unwrap_or(0) > 0 {
        let mut line = from_utf8(&buf).expect("expect line").trim().to_string();

        if state == 0 && line.starts_with("Domain Name:") {
            state = 1;
        }
        if state == 0 && line.starts_with("Server Name:") {
            referral_server = Some(String::new());
            state = 2;
        }
        if state == 1 && line.starts_with("Registrar WHOIS Server:") {
            let p = line.find(':').unwrap();
            line = line.split_off(p+1).trim().to_string();
            referral_server = Some(line.clone());
            state = 2;
        }

        if hide_line(&mut hide, &line) {
            continue;
        }

        println!("{}", line);
        buf.clear();
    }
    // Assuming error handling similar to ferror() is performed elsewhere.
    referral_server
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

fn open_conn(server: &str, port: Option<&str>) -> Result<TcpStream, Error> {
    let port = port.unwrap_or("43");
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


#[cfg(test)]
mod tests {
    use crate::whois_freebsd::{WHOIS_RECURSE, WHOIS_SPAM_ME};
    use super::*;

    #[test]
    fn whois_test() {
        let domain = normalize_domain("google.com");
        let conn = open_conn("whois.verisign-grs.com", None).expect("Expect connection>");
        let server = query_crsnic(&conn, domain.as_str()).expect("Expect result");

        println!("{:?}", server);
    }

    #[test]
    fn query_iana_test() {
        let conn = open_conn("whois.iana.org", None).expect("Expect connection>");
        let server = query_iana(&conn, "google.com");
        println!("{:?}", server);
    }

    #[test]
    fn whois_freebsd_test() {
        std::env::set_var("RUST_LOG", "debug");
        let domain = normalize_domain("club.dk");
        let r = whois_freebsd::whois(domain.as_str(),
                                     "whois.iana.org",
                                     "43",
                                     WHOIS_RECURSE);
    }
}
