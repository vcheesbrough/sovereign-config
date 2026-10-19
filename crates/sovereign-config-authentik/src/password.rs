//! The replacement app password a rotation sets on the account's token.

use sovereign_config_core::Secret;

const APP_PASSWORD_CHARS: usize = 48;
const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

/// The OS CSPRNG was unavailable.
#[derive(Debug)]
pub(crate) struct Unavailable;

/// Generates a high-entropy replacement app password from the OS CSPRNG,
/// drawing unbiased characters with rejection sampling.
pub(crate) fn generate_app_password() -> Result<Secret, Unavailable> {
    let limit = u8::MAX - (u8::MAX % u8::try_from(ALPHABET.len()).map_err(|_| Unavailable)?);
    let mut value = String::with_capacity(APP_PASSWORD_CHARS);
    while value.len() < APP_PASSWORD_CHARS {
        let mut buffer = [0_u8; 64];
        getrandom::fill(&mut buffer).map_err(|_| Unavailable)?;
        for byte in buffer {
            if byte < limit && value.len() < APP_PASSWORD_CHARS {
                value.push(char::from(ALPHABET[usize::from(byte) % ALPHABET.len()]));
            }
        }
    }
    Ok(Secret::new(value))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn app_passwords_are_long_alphanumeric_and_distinct() {
        let password = generate_app_password().unwrap();
        assert_eq!(password.expose().len(), 48);
        assert!(
            password
                .expose()
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric())
        );
        assert_ne!(password.expose(), generate_app_password().unwrap().expose());
    }
}
