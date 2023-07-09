use std::env;
use std::ffi::{CStr, CString};
use std::io::{self, BufRead, BufReader, BufWriter, Error, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::process::exit;
use std::str;
use std::time::Duration;
use crate::{hide_line, HIDE_NOT_STARTED};

const ABUSEHOST: &str = "whois.abuse.net";
const ANICHOST: &str = "whois.arin.net";
const DENICHOST: &str = "whois.denic.de";
const DKNICHOST: &str = "whois.dk-hostmaster.dk";
const FNICHOST: &str = "whois.afrinic.net";
const GNICHOST: &str = "whois.nic.gov";
const IANAHOST: &str = "whois.iana.org";
const INICHOST: &str = "whois.internic.net";
const KNICHOST: &str = "whois.krnic.net";
const LNICHOST: &str = "whois.lacnic.net";
const MNICHOST: &str = "whois.ra.net";
const PDBHOST: &str = "whois.peeringdb.com";
const PNICHOST: &str = "whois.apnic.net";
const QNICHOST_TAIL: &str = ".whois-servers.net";
const RNICHOST: &str = "whois.ripe.net";
const VNICHOST: &str = "whois.verisign-grs.com";

const DEFAULT_PORT: &str = "whois";

pub const WHOIS_RECURSE: u8 = 0x01;
const WHOIS_QUICK: u8 = 0x02;
pub const WHOIS_SPAM_ME: u8 = 0x04;

const CHOPSPAM: &str = ">>> Last update of WHOIS database:";

fn ishost(h: char) -> bool {
    h.is_ascii_alphanumeric() || h == '.' || h == '-'
}

struct WhoisServer {
    suffix: &'static str,
    server: &'static str,
}

static WHOIS_WHERE: &[WhoisServer] = &[
    /* Various handles */
    WhoisServer { suffix: "-ARIN", server: ANICHOST },
    WhoisServer { suffix: "-NICAT", server: "at" },
    WhoisServer { suffix: "-NORID", server: "no" },
    WhoisServer { suffix: "-RIPE", server: RNICHOST },
    /* Nominet's whois server doesn't return referrals to JANET */
    WhoisServer { suffix: ".ac.uk", server: "ac.uk" },
    WhoisServer { suffix: ".gov.uk", server: "ac.uk" },
    WhoisServer { suffix: "", server: IANAHOST }, /* default */
];

struct WhoisReferral {
    prefix: &'static str,
    len: usize,
}

static WHOIS_REFERRAL: &[WhoisReferral] = &[
    WhoisReferral { prefix: "whois:", len: 6 }, /* IANA */
    WhoisReferral { prefix: "Whois Server:", len: 14 },
    WhoisReferral { prefix: "Registrar WHOIS Server:", len: 24 }, /* corporatedomains.com */
    WhoisReferral { prefix: "ReferralServer:  whois://", len: 23 }, /* ARIN */
    WhoisReferral { prefix: "ReferralServer:  rwhois://", len: 24 }, /* ARIN */
    WhoisReferral { prefix: "descr:          region. Please query", len: 32 }, /* AfriNIC */
];

fn choose_server(domain: &str) -> &str {
    for server in WHOIS_WHERE {
        let suffix_len = server.suffix.len();
        if domain.len() > suffix_len && domain.ends_with(&server.suffix) {
            return server.server;
        }
    }
    panic!("No default whois server");
}

fn usage() {
    println!("Usage: whois [options] <query>");
    println!("Options:");
    println!("  -a\t\tSpecify ARIN whois server");
    println!("  -A\t\tSpecify APNIC whois server");
    println!("  -b\t\tSpecify Abuse.net whois server");
    println!("  -c <country>\tSpecify country code for a query");
    println!("  -f\t\tSpecify AFRINIC whois server");
    println!("  -g\t\tSpecify U.S. government whois server");
    println!("  -h <host>\tSpecify a specific whois server");
    println!("  -i\t\tSpecify InterNIC/IANA whois server");
    println!("  -I\t\tUse IANA as the default whois server");
    println!("  -k\t\tSpecify KISA (KRNIC) whois server");
    println!("  -l\t\tSpecify LACNIC whois server");
    println!("  -m\t\tSpecify MIL (S. America) whois server");
    println!("  -p <port>\tSpecify a custom whois port");
    println!("  -P\t\tSpecify PeeringDB whois server");
    println!("  -Q\t\tEnable quick mode (no recursion)");
    println!("  -r\t\tSpecify RIPE NCC whois server");
    println!("  -R\t\tEnable recursive lookups");
    println!("  -S\t\tEnable spam database checks");
    exit(1);
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

pub fn whois(query: &str, hostname: &str, hostport: &str, flags: u8) -> Result<(), Error> {
    let hostres = hostname;
    let stream = open_conn(hostres, None)?;

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
                let line = str::from_utf8(&buf).expect("Expect line");

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
                            let host = p.by_ref().take_while(|c| ishost(*c)).collect::<String>();
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
                if !should_spam_me && (line.starts_with(CHOPSPAM) || line.starts_with(&CHOPSPAM[4..])) {
                    println!();
                    break;
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

fn prepare_query(query: &str, flags: u8, hostname: &str) -> String {
    let should_spam_me = flags & WHOIS_SPAM_ME != 0;

    if !should_spam_me && (hostname.eq_ignore_ascii_case(DENICHOST) || hostname.eq_ignore_ascii_case(format!("de{:?}", QNICHOST_TAIL).as_str())) {
        let idn = query.chars().any(|c| !c.is_ascii());
        let dn_arg = if idn { "" } else { ",ace" };
        format!("-T dn{} {}", dn_arg, query)
    } else if !should_spam_me && (hostname.eq_ignore_ascii_case(DKNICHOST) || hostname.eq_ignore_ascii_case(format!("dk{:?}", QNICHOST_TAIL).as_str())) {
        let b = Box::new(String::from("AAAA"));
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