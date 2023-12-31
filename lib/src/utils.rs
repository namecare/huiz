use crate::error::Error;
use idna::domain_to_ascii;

/// Checks if a character is a valid host character.
///
/// This function determines whether a given character is valid for a host in a URL or a domain name.
/// The function considers a character as valid if it is an alphanumeric ASCII character, a period ('.'),
/// or a hyphen ('-').
///
/// # Arguments
///
/// * `h` - The character to check.
///
/// # Returns
///
/// Returns `true` if the character is a valid host character, and `false` otherwise.
///
/// # Examples
///
/// ```
/// use huiz::utils::is_host_char;
///
/// assert_eq!(is_host_char('a'), true);
/// assert_eq!(is_host_char('1'), true);
/// assert_eq!(is_host_char('.'), true);
/// assert_eq!(is_host_char('-'), true);
/// assert_eq!(is_host_char('@'), false);
/// assert_eq!(is_host_char(' '), false);
/// ```
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_host_characters() {
        assert_eq!(is_host_char('a'), true);
        assert_eq!(is_host_char('A'), true);
        assert_eq!(is_host_char('1'), true);
        assert_eq!(is_host_char('.'), true);
        assert_eq!(is_host_char('-'), true);
    }

    #[test]
    fn test_invalid_host_characters() {
        assert_eq!(is_host_char('@'), false);
        assert_eq!(is_host_char(' '), false);
        assert_eq!(is_host_char('_'), false);
    }
}

pub fn is_host_char(h: char) -> bool {
    h.is_ascii_alphanumeric() || h == '.' || h == '-'
}

/// Normalizes a domain string and converts the domain to ASCI.
///
/// # Arguments
///
/// * `domain` - The domain string to normalize.
///
/// # Returns
///
/// Returns a `Result` containing the normalized domain string on success (`Ok`),
/// or an `Error` indicating an invalid domain on failure (`Err`).
///
/// # Errors
///
/// The function can return an `Error::InvalidDomain` if the domain string is invalid.
///
/// # Examples
///
/// ```
/// use huiz::error::Error;
/// use huiz::utils::normalize_domain;
///
/// fn domain_to_ascii(domain: &str) -> Result<String, Error> {
///     // Implementation details...
///     # Ok("example.com".to_string())
/// }
///
/// let domain = "   example.com.  ";
/// let normalized = normalize_domain(domain);
/// assert_eq!(normalized.unwrap(), "example.com");
/// ```
#[cfg(test)]
mod normalize_domain_tests {
    use super::*;

    #[test]
    fn test_normalize_domain_trailing_characters() {
        let domain = "example.com.";
        let normalized = normalize_domain(domain).unwrap();
        assert_eq!(normalized, "example.com");
    }

    #[test]
    fn test_normalize_domain_whitespace_characters() {
        let domain = "   example.com.  ";
        let normalized = normalize_domain(domain).unwrap();
        assert_eq!(normalized, "example.com");
    }

    #[test]
    fn test_normalize_domain_spaces_in_domain() {
        let domain = "example domain";
        let result = normalize_domain(domain);
        assert!(result.is_err());
    }

    #[test]
    fn test_normalize_domain_invalid_domain() {
        let domain = "example@domain.com";
        let result = normalize_domain(domain);
        assert!(result.is_err());
    }
}

pub fn normalize_domain(domain: &str) -> Result<String, Error> {
    let trimmed_domain = domain.trim_matches(|c: char| c == '.' || c.is_whitespace());
    let invalid = trimmed_domain.contains(|c: char| !is_host_char(c));

    if invalid {
        return Err(Error::InvalidDomain);
    }

    domain_to_ascii(trimmed_domain)
        .map(|puny| puny)
        .map_err(|_e| Error::InvalidDomain)
}
