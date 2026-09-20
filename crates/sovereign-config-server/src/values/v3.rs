//! The `v3` wire shim over [`ConfigurationService`]: translation only.
//!
//! Each RPC builds the call context, restates its message in the shared
//! implementation's version-free terms, and encodes the result as `v3`. It
//! validates nothing and decides nothing. Input it cannot translate — an unset
//! oneof — is handed down as `None` for the shared implementation to reject,
//! so every protocol version fails a bad request with the same error and in
//! the same order. A second version is a sibling of this file, never an edit
//! to the shared implementation.

use std::sync::Arc;

use sovereign_config_core::{ValueClassification, ValueContent};
use sovereign_config_proto::sovereign::config::v3::{
    self, AddValuePathRequest, AddValuePathResponse, DeleteValuesRequest, DeleteValuesResponse,
    GetSubTreeRequest, GetSubTreeResponse, ListValuePathsRequest, ListValuePathsResponse,
    ListValuesRequest, ListValuesResponse, MaskedSecret, PutValueRequest, PutValueResponse,
    ReplaceSubTreeRequest, ReplaceSubTreeResponse, RevealSecretRequest, RevealSecretResponse,
    configuration_server::Configuration, listed_value, put_value_request, sub_tree_mutation_value,
    sub_tree_value,
};
use tonic::{Request, Response, Status};

use super::ConfigurationService;
use super::service::PutContent;
use super::subtree::{SubTreeEntry, SubTreeEntryContent};
use crate::rpc::{CallContext, to_proto_timestamp};

#[derive(Clone)]
pub(crate) struct V3Configuration {
    shared: Arc<ConfigurationService>,
}

impl V3Configuration {
    pub(crate) const fn new(shared: Arc<ConfigurationService>) -> Self {
        Self { shared }
    }
}

const fn classification(content: &ValueContent) -> i32 {
    match content.classification() {
        ValueClassification::Plain => v3::ValueClassification::Plain as i32,
        ValueClassification::Secret => v3::ValueClassification::Secret as i32,
    }
}

fn listed_content(content: ValueContent) -> listed_value::Content {
    match content {
        ValueContent::Plain(value) => listed_value::Content::PlainValue(value.into_inner()),
        ValueContent::Secret(_) => listed_value::Content::MaskedSecret(MaskedSecret {}),
    }
}

fn subtree_content(content: ValueContent) -> sub_tree_value::Content {
    match content {
        ValueContent::Plain(value) => sub_tree_value::Content::PlainValue(value.into_inner()),
        ValueContent::Secret(_) => sub_tree_value::Content::MaskedSecret(MaskedSecret {}),
    }
}

fn subtree_entry(value: v3::SubTreeMutationValue) -> SubTreeEntry {
    SubTreeEntry {
        path: value.path,
        content: value.content.map(|content| match content {
            sub_tree_mutation_value::Content::PlainValue(value) => {
                SubTreeEntryContent::PlainValue(value)
            }
            sub_tree_mutation_value::Content::PreserveSecret(_) => {
                SubTreeEntryContent::PreserveSecret
            }
        }),
    }
}

#[tonic::async_trait]
impl Configuration for V3Configuration {
    async fn list_values(
        &self,
        request: Request<ListValuesRequest>,
    ) -> Result<Response<ListValuesResponse>, Status> {
        let context = CallContext::from_request(&request);
        let listing = self
            .shared
            .list_values(&context, &request.get_ref().path)
            .await?;
        Ok(Response::new(ListValuesResponse {
            values: listing
                .values
                .into_iter()
                .map(|value| v3::ListedValue {
                    path: value.path.as_str().to_owned(),
                    created_at: Some(to_proto_timestamp(value.created_at)),
                    updated_at: Some(to_proto_timestamp(value.updated_at)),
                    classification: classification(&value.value),
                    content: Some(listed_content(value.value)),
                    alias_paths: value
                        .alias_paths
                        .iter()
                        .map(|path| path.as_str().to_owned())
                        .collect(),
                })
                .collect(),
            paths: listing
                .paths
                .iter()
                .map(|path| path.as_str().to_owned())
                .collect(),
        }))
    }

    async fn get_sub_tree(
        &self,
        request: Request<GetSubTreeRequest>,
    ) -> Result<Response<GetSubTreeResponse>, Status> {
        let context = CallContext::from_request(&request);
        let subtree = self
            .shared
            .get_sub_tree(&context, &request.get_ref().path)
            .await?;
        Ok(Response::new(GetSubTreeResponse {
            values: subtree
                .values
                .into_iter()
                .map(|value| v3::SubTreeValue {
                    path: value.path.as_str().to_owned(),
                    classification: classification(&value.value),
                    content: Some(subtree_content(value.value)),
                })
                .collect(),
        }))
    }

    async fn put_value(
        &self,
        request: Request<PutValueRequest>,
    ) -> Result<Response<PutValueResponse>, Status> {
        let context = CallContext::from_request(&request);
        let message = request.get_ref();
        let written = message.content.as_ref().map(|oneof| match oneof {
            put_value_request::Content::PlainValue(value) => PutContent::Plain(value),
            put_value_request::Content::SecretValue(value) => PutContent::Secret(value),
        });
        let metadata = self
            .shared
            .put_value(&context, &message.path, written)
            .await?;
        Ok(Response::new(PutValueResponse {
            created_at: Some(to_proto_timestamp(metadata.created_at)),
            updated_at: Some(to_proto_timestamp(metadata.updated_at)),
        }))
    }

    async fn replace_sub_tree(
        &self,
        request: Request<ReplaceSubTreeRequest>,
    ) -> Result<Response<ReplaceSubTreeResponse>, Status> {
        // Taken apart so the values move into their version-free form rather
        // than being cloned out of a borrowed message.
        let (_, extensions, message) = request.into_parts();
        let context = CallContext::from_extensions(&extensions);
        let values = message.values.into_iter().map(subtree_entry).collect();
        let metadata = self
            .shared
            .replace_sub_tree(&context, &message.path, values)
            .await?;
        Ok(Response::new(ReplaceSubTreeResponse {
            updated_at: Some(to_proto_timestamp(metadata.updated_at)),
            value_count: metadata.value_count,
        }))
    }

    async fn delete_values(
        &self,
        request: Request<DeleteValuesRequest>,
    ) -> Result<Response<DeleteValuesResponse>, Status> {
        let context = CallContext::from_request(&request);
        let message = request.get_ref();
        let metadata = self
            .shared
            .delete_values(&context, &message.path, message.recurse)
            .await?;
        Ok(Response::new(DeleteValuesResponse {
            deleted_at: Some(to_proto_timestamp(metadata.deleted_at)),
            deleted_count: metadata.deleted_count,
        }))
    }

    async fn reveal_secret(
        &self,
        request: Request<RevealSecretRequest>,
    ) -> Result<Response<RevealSecretResponse>, Status> {
        let context = CallContext::from_request(&request);
        let secret = self
            .shared
            .reveal_secret(&context, &request.get_ref().path)
            .await?;
        Ok(Response::new(RevealSecretResponse {
            value: secret.expose().to_owned(),
        }))
    }

    async fn add_value_path(
        &self,
        request: Request<AddValuePathRequest>,
    ) -> Result<Response<AddValuePathResponse>, Status> {
        let context = CallContext::from_request(&request);
        let message = request.get_ref();
        let metadata = self
            .shared
            .add_value_path(&context, &message.source_path, &message.new_path)
            .await?;
        Ok(Response::new(AddValuePathResponse {
            created_at: Some(to_proto_timestamp(metadata.created_at)),
        }))
    }

    async fn list_value_paths(
        &self,
        request: Request<ListValuePathsRequest>,
    ) -> Result<Response<ListValuePathsResponse>, Status> {
        let context = CallContext::from_request(&request);
        let paths = self
            .shared
            .list_value_paths(&context, &request.get_ref().path)
            .await?;
        Ok(Response::new(ListValuePathsResponse {
            paths: paths
                .paths
                .iter()
                .map(|path| path.as_str().to_owned())
                .collect(),
        }))
    }
}
