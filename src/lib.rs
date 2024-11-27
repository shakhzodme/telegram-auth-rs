use hmac::{Hmac, Mac};
use serde_json::Value;
use sha2::{Digest, Sha256};

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, PartialEq)]
pub enum ValidationError {
    InvalidInput,
    InvalidHash,
}

fn extract_data_check_string(value: Value) -> Result<(String, String), ValidationError> {
    match value {
        Value::Object(object) => {
            let kv = object
                .into_iter()
                .filter_map(|(key, value)| {
                    (match value {
                        Value::Number(n) => n.as_i64().map(|n| n.to_string()),
                        Value::String(s) => Some(s),
                        _ => None,
                    })
                    .map(|value| (key, value))
                })
                .collect::<std::collections::BTreeMap<String, String>>();

            let hash = kv
                .get("hash")
                .ok_or(ValidationError::InvalidInput)?
                .to_string();

            Ok((
                hash,
                kv.iter()
                    .filter(|(key, _)| key != &"hash")
                    .map(|(key, value)| format!("{}={}", key, value))
                    .collect::<Vec<_>>()
                    .join("\n"),
            ))
        }
        _ => Err(ValidationError::InvalidInput),
    }
}

pub fn validate(input: &str, bot_token: &str) -> Result<(), ValidationError> {
    let (check_hash, data_check_string) = serde_json::from_str(input)
        .map_err(|_| ValidationError::InvalidInput)
        .map(extract_data_check_string)??;

    let bot_token_hash = Sha256::digest(bot_token.as_bytes());

    let mut mac =
        HmacSha256::new_from_slice(&bot_token_hash).map_err(|_| ValidationError::InvalidInput)?;
    mac.update(data_check_string.as_bytes());

    let result = hex::encode(mac.finalize().into_bytes());

    if result == check_hash {
        Ok(())
    } else {
        Err(ValidationError::InvalidHash)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID_BOT_TOKEN: &'static str = "123456:ABC-DEF1234ghIkl-zyx57W2v1u123ew11";
    const VALID_DATA: &'static str = r#"
        {
            "id": 12345678,
            "first_name":"Name",
            "username":"username",
            "photo_url":"https://photourl",
            "auth_date":1732679640,
            "hash":"5f6e5338e6522038abe1ce21b21c675337535cc332a727bce8148dd62588097e"
        }"#;

    const INVALID_BOT_TOKEN: &'static str = "654321:ABC-DEF1234ghIkl-zyx57W2v1u123ew11";
    const INVALID_DATA: &'static str = r#"
        {
            "id": 12345678,
            "first_name":"Name",
            "username":"username",
            "photo_url":"https://photourl",
            "auth_date":1732679640,
            "hash":"605c4ad6d7d25df74071df9b8956dea769c5b65fa0ba09c22bf28caf1bc7d4bb"
        }"#;

    #[test]
    fn valid_data_valid_bot_token() {
        assert_eq!(validate(VALID_DATA, VALID_BOT_TOKEN), Ok(()));
    }

    #[test]
    fn valid_data_invalid_bot_token() {
        assert_eq!(
            validate(VALID_DATA, INVALID_BOT_TOKEN),
            Err(ValidationError::InvalidHash)
        );
    }

    #[test]
    fn invalid_data_valid_bot_token() {
        assert_eq!(
            validate(INVALID_DATA, VALID_BOT_TOKEN),
            Err(ValidationError::InvalidHash)
        );
    }

    #[test]
    fn arbitrary_data() {
        assert_eq!(
            validate("blabla", VALID_BOT_TOKEN),
            Err(ValidationError::InvalidInput)
        );
    }
}
