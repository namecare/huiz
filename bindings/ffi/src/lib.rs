use huiz::error::Error;
pub use huiz::Whois;
use huiz::WhoisResult;

uniffi::include_scaffolding!("huiz");

pub type HuizError = Error;

pub fn whois(q: String) -> Result<WhoisResult, Error> {
    huiz::whois(q.as_str())
}
