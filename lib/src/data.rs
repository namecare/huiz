pub const ABUSEHOST: &str = "whois.abuse.net";
pub const ANICHOST: &str = "whois.arin.net";
pub const DENICHOST: &str = "whois.denic.de";
pub const DKNICHOST: &str = "whois.dk-hostmaster.dk";
pub const FNICHOST: &str = "whois.afrinic.net";
pub const GNICHOST: &str = "whois.nic.gov";
pub const IANAHOST: &str = "whois.iana.org";
pub const INICHOST: &str = "whois.internic.net";
pub const KNICHOST: &str = "whois.krnic.net";
pub const LNICHOST: &str = "whois.lacnic.net";
pub const MNICHOST: &str = "whois.ra.net";
pub const PDBHOST: &str = "whois.peeringdb.com";
pub const PNICHOST: &str = "whois.apnic.net";
pub const QNICHOST_TAIL: &str = ".whois-servers.net";
pub const RNICHOST: &str = "whois.ripe.net";
pub const VNICHOST: &str = "whois.verisign-grs.com";

pub const DEFAULT_PORT: &str = "43";

pub struct WhoisServer {
    pub suffix: &'static str,
    pub server: &'static str,
}

pub static WHOIS_WHERE: &[WhoisServer] = &[
    /* Various handles */
    WhoisServer { suffix: "-ARIN", server: ANICHOST },
    WhoisServer { suffix: "-NICAT", server: "at.whois-servers.net" },
    WhoisServer { suffix: "-NORID", server: "no.whois-servers.net" },
    WhoisServer { suffix: "-RIPE", server: RNICHOST },

    /* Nominet's whois server doesn't return referrals to JANET */
    WhoisServer { suffix: ".ac.uk", server: "ac.uk.whois-servers.net" },
    WhoisServer { suffix: ".gov.uk", server: "ac.uk.whois-servers.net" },
    WhoisServer { suffix: "", server: IANAHOST }, /* default */
];

pub struct WhoisReferral {
    pub prefix: &'static str,
    pub len: usize,
}

pub static WHOIS_REFERRAL: &[WhoisReferral] = &[
    WhoisReferral { prefix: "whois:", len: 6 }, /* IANA */
    WhoisReferral { prefix: "Whois Server:", len: 14 },
    WhoisReferral { prefix: "Registrar WHOIS Server:", len: 24 }, /* corporatedomains.com */
    WhoisReferral { prefix: "ReferralServer:  whois://", len: 23 }, /* ARIN */
    WhoisReferral { prefix: "ReferralServer:  rwhois://", len: 24 }, /* ARIN */
    WhoisReferral { prefix: "descr:          region. Please query", len: 32 }, /* AfriNIC */
];