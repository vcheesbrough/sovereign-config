#![forbid(unsafe_code)]

#[cfg(test)]
mod tests {
    use std::{cell::RefCell, collections::BTreeMap};

    use async_trait::async_trait;
    use sovereign_config_client::{
        AccessTokenProvider, Client, Transport, ValueTransport, VersionReply,
    };
    use sovereign_config_core::{
        AuthenticationStatus, ClientError, ConfigPath, DeleteMetadata, ErrorKind, ListedValue,
        PlainValue, PutMetadata, ReplaceMetadata, Secret, SubTreeValue, Timestamp, ValueListing,
        ValueSubTree,
    };

    #[derive(Clone)]
    struct StoredValue {
        value: PlainValue,
        created_at: Timestamp,
        updated_at: Timestamp,
    }

    struct ConsumerTransport {
        values: RefCell<BTreeMap<ConfigPath, StoredValue>>,
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
        async fn list_values(
            &self,
            path: &ConfigPath,
            _: &Secret,
        ) -> Result<ValueListing, ClientError> {
            let values = self
                .values
                .borrow()
                .iter()
                .filter(|(candidate, _)| {
                    candidate
                        .as_str()
                        .rsplit_once('/')
                        .map_or("", |(parent, _)| parent)
                        == path.as_str()
                })
                .map(|(path, value)| ListedValue {
                    path: path.clone(),
                    value: value.value.clone(),
                    created_at: value.created_at,
                    updated_at: value.updated_at,
                })
                .collect();
            Ok(ValueListing {
                values,
                paths: vec![path.clone()],
            })
        }

        async fn get_subtree(
            &self,
            path: &ConfigPath,
            _: &Secret,
        ) -> Result<ValueSubTree, ClientError> {
            Ok(ValueSubTree {
                values: self
                    .values
                    .borrow()
                    .iter()
                    .filter(|(candidate, _)| candidate.is_at_or_below(path))
                    .map(|(path, value)| SubTreeValue {
                        path: path.clone(),
                        value: value.value.clone(),
                    })
                    .collect(),
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
                StoredValue {
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

        async fn replace_subtree(
            &self,
            path: &ConfigPath,
            values: &[SubTreeValue],
            _: &Secret,
        ) -> Result<ReplaceMetadata, ClientError> {
            let timestamp = Timestamp {
                seconds: 1_700_000_001,
                nanos: 0,
            };
            let mut stored = self.values.borrow_mut();
            stored.retain(|candidate, _| !candidate.is_at_or_below(path));
            for value in values {
                stored.insert(
                    value.path.clone(),
                    StoredValue {
                        value: value.value.clone(),
                        created_at: timestamp,
                        updated_at: timestamp,
                    },
                );
            }
            Ok(ReplaceMetadata {
                updated_at: timestamp,
                value_count: values.len() as u64,
            })
        }

        async fn delete_values(
            &self,
            path: &ConfigPath,
            recurse: bool,
            _: &Secret,
        ) -> Result<DeleteMetadata, ClientError> {
            let mut values = self.values.borrow_mut();
            let before = values.len();
            if recurse {
                values.retain(|candidate, _| !candidate.is_at_or_below(path));
            } else {
                values.remove(path);
            }
            let deleted_count = u64::try_from(before - values.len()).unwrap();
            if deleted_count == 0 {
                return Err(ClientError::new(
                    ErrorKind::NotFound,
                    "configuration value not found",
                ));
            }
            Ok(DeleteMetadata {
                deleted_at: Timestamp {
                    seconds: 1_700_000_001,
                    nanos: 0,
                },
                deleted_count,
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
    async fn public_client_api_supports_the_v2_value_lifecycle() {
        let client = Client::new(
            ConsumerTransport {
                values: RefCell::new(BTreeMap::new()),
            },
            ConsumerAuthentication,
        );
        let path = ConfigPath::parse_operation("/Apps/API/Feature").unwrap();
        let value = PlainValue::new("consumer-value-sentinel");

        client.put_value(&path, &value).await.unwrap();
        let listing = client
            .list_values(&ConfigPath::parse("/apps/api").unwrap())
            .await
            .unwrap();
        assert_eq!(listing.values.len(), 1);
        assert_eq!(listing.values[0].path, path);
        assert_eq!(
            client.get_subtree(&path).await.unwrap().values[0]
                .value
                .expose(),
            "consumer-value-sentinel"
        );
        let child = SubTreeValue {
            path: ConfigPath::parse("/apps/api/feature/child").unwrap(),
            value: PlainValue::new("child"),
        };
        client
            .replace_subtree(&path, std::slice::from_ref(&child))
            .await
            .unwrap();
        assert_eq!(client.get_subtree(&path).await.unwrap().values, vec![child]);
        assert_eq!(
            client
                .delete_values(&path, true)
                .await
                .unwrap()
                .deleted_count,
            1
        );
        assert!(client.get_subtree(&path).await.unwrap().values.is_empty());
    }
}
