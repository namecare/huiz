use std::io::{BufRead, BufReader, Write};
use std::net::TcpStream;
use std::str::from_utf8;
use crate::{hide_line, HIDE_NOT_STARTED, HIDE_TO_THE_END};

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
