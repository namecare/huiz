use std::io::{BufRead, BufReader, Write};
use std::net::TcpStream;
use std::str::from_utf8;
use crate::{hide_line, HIDE_NOT_STARTED};

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