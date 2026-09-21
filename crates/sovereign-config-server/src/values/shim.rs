//! The one `Configuration` adapter every protocol version's shim instantiates.
//!
//! Each version's generated types live in their own package, so one adapter
//! cannot be written against all of them as ordinary code: the types differ
//! even where their shape does not. [`configuration_shim`] is that adapter,
//! written once, and a version's shim is one invocation of it naming the
//! version's generated package as `proto` and choosing a [`Validation`]. It is
//! never copied and never chained: a shim never calls another version's shim,
//! so retiring a version is deleting its file.
//!
//! The macro is only proto↔core translation. Everything it calls is the shared
//! implementation in `service.rs`, which never learns which version it serves.
//! A version whose message *shape* differs from the others gets its own adapter
//! for that operation rather than a branch in this one.

use tonic::Status;

use super::service::PutContent;
use super::subtree::SubTreeEntry;

/// What a version's shim checks before it calls the shared implementation.
///
/// Version-free, so a version chooses its policy rather than writing one:
/// the checks see only the translated inputs, never a generated type.
pub(super) trait Validation {
    /// A `PutValue`'s content, before authorization.
    #[expect(
        clippy::result_large_err,
        reason = "tonic::Status is the crate's RPC error type and is returned by value"
    )]
    fn put_value(written: Option<&PutContent<'_>>) -> Result<(), Status>;

    /// A `ReplaceSubTree`'s entries, before authorization.
    #[expect(
        clippy::result_large_err,
        reason = "tonic::Status is the crate's RPC error type and is returned by value"
    )]
    fn replace_sub_tree(values: &[SubTreeEntry]) -> Result<(), Status>;
}

/// **`v3`'s policy: validate nothing here.** An unset oneof goes down as `None`
/// and the shared implementation rejects it — after it has authorized, which
/// is the order `v3` has always failed in. Moving the check up here would
/// reorder `v3`'s errors, and that is a behaviour change, so a new version.
pub(super) struct Deferred;

impl Validation for Deferred {
    fn put_value(_: Option<&PutContent<'_>>) -> Result<(), Status> {
        Ok(())
    }

    fn replace_sub_tree(_: &[SubTreeEntry]) -> Result<(), Status> {
        Ok(())
    }
}

/// **The policy from `v4` on: a malformed request is refused before anyone is
/// asked whether they may make it.** The wording is the shared
/// implementation's own, so a client sees the same message on every version
/// and only the order differs.
pub(super) struct Upfront;

impl Validation for Upfront {
    fn put_value(written: Option<&PutContent<'_>>) -> Result<(), Status> {
        match written {
            None => Err(Status::invalid_argument("configuration value is invalid")),
            Some(PutContent::Plain(value) | PutContent::Secret(value)) if value.contains('\0') => {
                Err(Status::invalid_argument(
                    "configuration value contains an invalid character",
                ))
            }
            Some(_) => Ok(()),
        }
    }

    fn replace_sub_tree(values: &[SubTreeEntry]) -> Result<(), Status> {
        if values.iter().any(|value| value.content.is_none()) {
            return Err(Status::invalid_argument("configuration subtree is invalid"));
        }
        Ok(())
    }
}

/// Defines `$shim`, the tonic `Configuration` impl for the generated package
/// the invoking module imports as `proto`, validating with `$validation`.
///
/// Paths in the body resolve where the macro is invoked — a `values/vN.rs`
/// shim — which is what lets `proto` name a different package in each.
macro_rules! configuration_shim {
    ($shim:ident, $validation:ty) => {
        #[derive(Clone)]
        pub(crate) struct $shim {
            shared: std::sync::Arc<super::ConfigurationService>,
        }

        impl $shim {
            pub(crate) const fn new(shared: std::sync::Arc<super::ConfigurationService>) -> Self {
                Self { shared }
            }
        }

        const fn classification(content: &sovereign_config_core::ValueContent) -> i32 {
            match content.classification() {
                sovereign_config_core::ValueClassification::Plain => {
                    proto::ValueClassification::Plain as i32
                }
                sovereign_config_core::ValueClassification::Secret => {
                    proto::ValueClassification::Secret as i32
                }
            }
        }

        fn listed_content(
            content: sovereign_config_core::ValueContent,
        ) -> proto::listed_value::Content {
            match content {
                sovereign_config_core::ValueContent::Plain(value) => {
                    proto::listed_value::Content::PlainValue(value.into_inner())
                }
                sovereign_config_core::ValueContent::Secret(_) => {
                    proto::listed_value::Content::MaskedSecret(proto::MaskedSecret {})
                }
            }
        }

        fn subtree_content(
            content: sovereign_config_core::ValueContent,
        ) -> proto::sub_tree_value::Content {
            match content {
                sovereign_config_core::ValueContent::Plain(value) => {
                    proto::sub_tree_value::Content::PlainValue(value.into_inner())
                }
                sovereign_config_core::ValueContent::Secret(_) => {
                    proto::sub_tree_value::Content::MaskedSecret(proto::MaskedSecret {})
                }
            }
        }

        fn subtree_entry(value: proto::SubTreeMutationValue) -> super::subtree::SubTreeEntry {
            super::subtree::SubTreeEntry {
                path: value.path,
                content: value.content.map(|content| match content {
                    proto::sub_tree_mutation_value::Content::PlainValue(value) => {
                        super::subtree::SubTreeEntryContent::PlainValue(value)
                    }
                    proto::sub_tree_mutation_value::Content::PreserveSecret(_) => {
                        super::subtree::SubTreeEntryContent::PreserveSecret
                    }
                }),
            }
        }

        fn path_strings(paths: &[sovereign_config_core::ConfigPath]) -> Vec<String> {
            paths.iter().map(|path| path.as_str().to_owned()).collect()
        }

        #[tonic::async_trait]
        impl proto::configuration_server::Configuration for $shim {
            async fn list_values(
                &self,
                request: tonic::Request<proto::ListValuesRequest>,
            ) -> Result<tonic::Response<proto::ListValuesResponse>, tonic::Status> {
                let context = crate::rpc::CallContext::from_request(&request);
                let listing = self
                    .shared
                    .list_values(&context, &request.get_ref().path)
                    .await?;
                Ok(tonic::Response::new(proto::ListValuesResponse {
                    values: listing
                        .values
                        .into_iter()
                        .map(|value| proto::ListedValue {
                            path: value.path.as_str().to_owned(),
                            created_at: Some(crate::rpc::to_proto_timestamp(value.created_at)),
                            updated_at: Some(crate::rpc::to_proto_timestamp(value.updated_at)),
                            classification: classification(&value.value),
                            alias_paths: path_strings(&value.alias_paths),
                            content: Some(listed_content(value.value)),
                        })
                        .collect(),
                    paths: path_strings(&listing.paths),
                }))
            }

            async fn get_sub_tree(
                &self,
                request: tonic::Request<proto::GetSubTreeRequest>,
            ) -> Result<tonic::Response<proto::GetSubTreeResponse>, tonic::Status> {
                let context = crate::rpc::CallContext::from_request(&request);
                let subtree = self
                    .shared
                    .get_sub_tree(&context, &request.get_ref().path)
                    .await?;
                Ok(tonic::Response::new(proto::GetSubTreeResponse {
                    values: subtree
                        .values
                        .into_iter()
                        .map(|value| proto::SubTreeValue {
                            path: value.path.as_str().to_owned(),
                            classification: classification(&value.value),
                            content: Some(subtree_content(value.value)),
                        })
                        .collect(),
                }))
            }

            async fn put_value(
                &self,
                request: tonic::Request<proto::PutValueRequest>,
            ) -> Result<tonic::Response<proto::PutValueResponse>, tonic::Status> {
                let context = crate::rpc::CallContext::from_request(&request);
                let message = request.get_ref();
                let written = message.content.as_ref().map(|oneof| match oneof {
                    proto::put_value_request::Content::PlainValue(value) => {
                        super::service::PutContent::Plain(value)
                    }
                    proto::put_value_request::Content::SecretValue(value) => {
                        super::service::PutContent::Secret(value)
                    }
                });
                <$validation as super::shim::Validation>::put_value(written.as_ref())?;
                let metadata = self
                    .shared
                    .put_value(&context, &message.path, written)
                    .await?;
                Ok(tonic::Response::new(proto::PutValueResponse {
                    created_at: Some(crate::rpc::to_proto_timestamp(metadata.created_at)),
                    updated_at: Some(crate::rpc::to_proto_timestamp(metadata.updated_at)),
                }))
            }

            async fn replace_sub_tree(
                &self,
                request: tonic::Request<proto::ReplaceSubTreeRequest>,
            ) -> Result<tonic::Response<proto::ReplaceSubTreeResponse>, tonic::Status> {
                // Taken apart so the values move into their version-free form
                // rather than being cloned out of a borrowed message.
                let (_, extensions, message) = request.into_parts();
                let context = crate::rpc::CallContext::from_extensions(&extensions);
                let values: Vec<_> = message.values.into_iter().map(subtree_entry).collect();
                <$validation as super::shim::Validation>::replace_sub_tree(&values)?;
                let metadata = self
                    .shared
                    .replace_sub_tree(&context, &message.path, values)
                    .await?;
                Ok(tonic::Response::new(proto::ReplaceSubTreeResponse {
                    updated_at: Some(crate::rpc::to_proto_timestamp(metadata.updated_at)),
                    value_count: metadata.value_count,
                }))
            }

            async fn delete_values(
                &self,
                request: tonic::Request<proto::DeleteValuesRequest>,
            ) -> Result<tonic::Response<proto::DeleteValuesResponse>, tonic::Status> {
                let context = crate::rpc::CallContext::from_request(&request);
                let message = request.get_ref();
                let metadata = self
                    .shared
                    .delete_values(&context, &message.path, message.recurse)
                    .await?;
                Ok(tonic::Response::new(proto::DeleteValuesResponse {
                    deleted_at: Some(crate::rpc::to_proto_timestamp(metadata.deleted_at)),
                    deleted_count: metadata.deleted_count,
                }))
            }

            async fn reveal_secret(
                &self,
                request: tonic::Request<proto::RevealSecretRequest>,
            ) -> Result<tonic::Response<proto::RevealSecretResponse>, tonic::Status> {
                let context = crate::rpc::CallContext::from_request(&request);
                let secret = self
                    .shared
                    .reveal_secret(&context, &request.get_ref().path)
                    .await?;
                Ok(tonic::Response::new(proto::RevealSecretResponse {
                    value: secret.expose().to_owned(),
                }))
            }

            async fn add_value_path(
                &self,
                request: tonic::Request<proto::AddValuePathRequest>,
            ) -> Result<tonic::Response<proto::AddValuePathResponse>, tonic::Status> {
                let context = crate::rpc::CallContext::from_request(&request);
                let message = request.get_ref();
                let metadata = self
                    .shared
                    .add_value_path(
                        &context,
                        super::service::AliasPaths {
                            source: &message.source_path,
                            new_path: &message.new_path,
                        },
                    )
                    .await?;
                Ok(tonic::Response::new(proto::AddValuePathResponse {
                    created_at: Some(crate::rpc::to_proto_timestamp(metadata.created_at)),
                }))
            }

            async fn list_value_paths(
                &self,
                request: tonic::Request<proto::ListValuePathsRequest>,
            ) -> Result<tonic::Response<proto::ListValuePathsResponse>, tonic::Status> {
                let context = crate::rpc::CallContext::from_request(&request);
                let paths = self
                    .shared
                    .list_value_paths(&context, &request.get_ref().path)
                    .await?;
                Ok(tonic::Response::new(proto::ListValuePathsResponse {
                    paths: path_strings(&paths.paths),
                }))
            }
        }
    };
}

pub(super) use configuration_shim;
