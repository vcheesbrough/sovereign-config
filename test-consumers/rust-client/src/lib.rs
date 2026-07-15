#![forbid(unsafe_code)]

#[cfg(test)]
mod tests {
    use std::{cell::RefCell, collections::BTreeMap};

    use async_trait::async_trait;
    use sovereign_config_client::{
        AccessTokenProvider, Client, Transport, ValueTransport, VersionReply,
    };
    use sovereign_config_core::{
        AuthenticationStatus, ClientError, ConfigPath, DeleteMetadata, ErrorKind, ExactValue,
        PlainValue, PutMetadata, Secret, Timestamp,
    };

    struct ConsumerTransport {
        values: RefCell<BTreeMap<ConfigPath, ExactValue>>,
    }

    #[async_trait(?Send)]
    impl Transport for ConsumerTransport {
        async fn get_version(&self, protocol_version: &str) -> Result<VersionReply, ClientError> {
            Ok(VersionReply {
                application_version: "consumer-fixture".into(),
                protocol_version: protocol_version.into(),
            })
        }

        async fn get_identity(&self, _: &Secret) -> Result<AuthenticationStatus, ClientError> {
            Ok(AuthenticationStatus {
                authenticated: true,
            })
        }
    }

    #[async_trait(?Send)]
    impl ValueTransport for ConsumerTransport {
        async fn get_value(
            &self,
            path: &ConfigPath,
            _: &Secret,
        ) -> Result<ExactValue, ClientError> {
            self.values.borrow().get(path).cloned().ok_or_else(|| {
                ClientError::new(ErrorKind::NotFound, "configuration value not found")
            })
        }

        async fn put_value(
            &self,
            path: &ConfigPath,
            value: &PlainValue,
            _: &Secret,
        ) -> Result<PutMetadata, ClientError> {
            let timestamp = Timestamp {
                seconds: 1_700_000_000,
                nanos: 0,
            };
            self.values.borrow_mut().insert(
                path.clone(),
                ExactValue {
                    value: value.clone(),
                    created_at: timestamp,
                    updated_at: timestamp,
                },
            );
            Ok(PutMetadata {
                created_at: timestamp,
                updated_at: timestamp,
            })
        }

        async fn delete_value(
            &self,
            path: &ConfigPath,
            _: &Secret,
        ) -> Result<DeleteMetadata, ClientError> {
            self.values.borrow_mut().remove(path).ok_or_else(|| {
                ClientError::new(ErrorKind::NotFound, "configuration value not found")
            })?;
            Ok(DeleteMetadata {
                deleted_at: Timestamp {
                    seconds: 1_700_000_001,
                    nanos: 0,
                },
            })
        }
    }

    struct ConsumerAuthentication;

    #[async_trait(?Send)]
    impl AccessTokenProvider for ConsumerAuthentication {
        async fn access_token(&self) -> Result<Option<Secret>, ClientError> {
            Ok(Some(Secret::new("consumer-token-sentinel")))
        }
    }

    #[tokio::test]
    async fn public_client_api_supports_the_exact_value_lifecycle() {
        let client = Client::new(
            ConsumerTransport {
                values: RefCell::new(BTreeMap::new()),
            },
            ConsumerAuthentication,
        );
        let path = ConfigPath::parse_operation("Apps/API/Feature").unwrap();
        let value = PlainValue::new("consumer-value-sentinel");

        client.put_value(&path, &value).await.unwrap();
        assert_eq!(
            client.get_value(&path).await.unwrap().value.expose(),
            "consumer-value-sentinel"
        );
        client.delete_value(&path).await.unwrap();
        assert_eq!(
            client.get_value(&path).await.unwrap_err().kind,
            ErrorKind::NotFound
        );
    }
}
