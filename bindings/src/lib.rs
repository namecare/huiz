pub use huiz::Whois;
use huiz::WhoisResult;

#[derive(uniffi::Error, Debug)]
pub enum HuizError {
    Error,
}

#[uniffi::export]
pub fn whois(q: String) -> Result<WhoisResult, HuizError> {
    Ok(huiz::whois(q.as_str()).expect("e"))
}

uniffi::include_scaffolding!("huiz_ffi");
