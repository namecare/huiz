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

pub const HIDE_STRINGS: &[Option<&str>] = &[
    Some("The data in Networksolutions.com's WHOIS database"), None,
    Some("TERMS OF USE: You are not authorized"), None,
    Some("The data in Register.com's WHOIS database"), None,
    Some("The Data in the Tucows Registrar WHOIS database"), None,
    Some("TERMS OF USE: The Data in Gabia' WHOIS"), None,
    Some("The data contained in GoDaddy.com"), None,
    Some("Personal data access and use are governed by French"), None,
    Some("The data in this whois database is provided to you"), None,
    Some("Please register your domains at; http://www."), None,
    Some("%% NOTICE: Access to this information is provided"), None,
    Some("NOTICE: Access to the domain name's information"), None,
    Some("NOTICE: The expiration date"), None,

    Some("The Data in MarkMonitor.com's"), None,
    Some("Corporation Service Company(c) (CSC)  The Trusted Partner"), Some("Register your domain name at"),
    Some("The data in Networksolutions.com's"), None,
    Some("# Welcome to the OVH WHOIS Server"), Some(""),
    Some("TERMS OF USE OF MELBOURNE IT WHOIS DATABASE"), None,
    Some("The data contained in this Registrar's Whois"), None,
    Some("The data in the FastDomain Inc. WHOIS database"), None,
    Some("Access to WHOIS information is provided"), None,
    Some("This Registry database contains ONLY .EDU"), Some("domain names."),
    Some("Access to AFILIAS WHOIS information is provided"), None,
    Some("Access to Public Interest Registry WHOIS information"), None,
    Some("Telnames Limited, the Registry Operator for"), None,
    Some("Tralliance, Inc., the Registry Operator for .travel"), None,
    Some("The data in this record is provided by"), None,
    Some("Terms of Use: Donuts Inc. provides"), None,
    Some("Access to WHOIS information is provided"), None,
    Some("TERMS OF USE: You  are  not  authorized"), None,
    Some("The Whois and RDAP services are provided by CentralNic"), Some(""),
    Some(".Club Domains, LLC, the Registry Operator"), None,
    Some("% Except for agreed Internet operational purposes"), None,
    Some("TERMS OF USE: The information in the Whois database"), None,
    Some("The WHOIS service offered by Neustar, Inc, on behalf"), None,
    Some("The WHOIS service offered by the Registry Operator"), None,
    Some("Access to CCTLD WHOIS information is provided"), Some(""),
    Some("This WHOIS information is provided"), None,
    Some("% The WHOIS service offered by DNS Belgium"), Some(""),
    Some(".CO Internet, S.A.S., the Administrator"), None,
    Some("%  *The information provided"), Some("% https://www.nic.cr/iniciar-sesion/?next=/mi-cuenta/"),
    Some("% The WHOIS service offered by EURid"), Some("% of the database"),
    Some("Access to .IN WHOIS information"), None,
    Some("access to .in whois information"), None,
    Some("% Use of CIRA's WHOIS service is governed by the Terms of Use in its Legal"), None,
    Some("The Service is provided so that you may look"), Some("We may discontinue"),
    Some("NeuStar, Inc., the Registry Administrator for .US"), None,
    Some("Web-based WHOIS"), None,
    Some("If you wish"), None,
    Some("For more information on Whois"), None,
    Some("If you have"), None,
    Some("The data in"), None,
    None, None
];
