pub use huiz::Whois;

uniffi::include_scaffolding!("huiz");

pub fn query(q: String) -> Whois {
    Whois {
        raw: "134".to_string()
    }
}
