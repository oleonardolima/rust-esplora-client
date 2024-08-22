// Bitcoin Dev Kit
// Written in 2020 by Alekos Filini <alekos.filini@gmail.com>
//
// Copyright (c) 2020-2021 Bitcoin Dev Kit Developers
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Esplora by way of `reqwest` HTTP client.

use std::collections::HashMap;
use std::str::FromStr;

use bitcoin::consensus::{deserialize, serialize, Decodable};
use bitcoin::hashes::{sha256, Hash};
use bitcoin::hex::{DisplayHex, FromHex};
use bitcoin::{
    block::Header as BlockHeader, Block, BlockHash, MerkleBlock, Script, Transaction, Txid,
};

#[allow(unused_imports)]
use log::{debug, error, info, trace};

use reqwest::{header, Client};

use crate::{BlockStatus, BlockSummary, Builder, Error, MerkleProof, OutputStatus, Tx, TxStatus};

#[async_trait::async_trait]
pub trait AsyncEsploraClient {
    /// Make an HTTP GET request to given URL, deserializing to any `T` that
    /// implement [`bitcoin::consensus::Decodable`].
    ///
    /// It should be used when requesting Esplora endpoints that can be directly
    /// deserialized to native `rust-bitcoin` types, which implements
    /// [`bitcoin::consensus::Decodable`] from `&[u8]`.
    ///
    /// # Errors
    ///
    /// This function will return an error either from the HTTP client, or the
    /// [`bitcoin::consensus::Decodable`] deserialization.
    async fn get_response<T: Decodable>(&self, url: &str) -> Result<T, Error>;

    /// Make an HTTP GET request to given URL, deserializing to `Option<T>`.
    ///
    /// It uses [`AsyncEsploraClient::get_response`] internally.
    ///
    /// See [`AsyncEsploraClient::get_response`] above for full documentation.
    async fn get_opt_response<T: Decodable>(&self, url: &str) -> Result<Option<T>, Error>;

    /// Make an HTTP GET request to given URL, deserializing to any `T` that
    /// implements [`serde::de::DeserializeOwned`].
    ///
    /// It should be used when requesting Esplora endpoints that have a specific
    /// defined API, mostly defined in [`crate::api`].
    ///
    /// # Errors
    ///
    /// This function will return an error either from the HTTP client, or the
    /// [`serde::de::DeserializeOwned`] deserialization.
    async fn get_response_json<T: serde::de::DeserializeOwned>(
        &self,
        url: &str,
    ) -> Result<T, Error>;

    /// Make an HTTP GET request to given URL, deserializing to `Option<T>`.
    ///
    /// It uses [`AsyncEsploraClient::get_response_json`] internally.
    ///
    /// See [`AsyncEsploraClient::get_response_json`] above for full
    /// documentation.
    async fn get_opt_response_json<T: serde::de::DeserializeOwned>(
        &self,
        url: &str,
    ) -> Result<Option<T>, Error>;

    /// Make an HTTP GET request to given URL, deserializing to any `T` that
    /// implement [`bitcoin::consensus::Decodable`] from Hex, [`Vec<u8>`].
    ///
    /// It should be used when requesting Esplora endpoints that can be directly
    /// deserialized to native `rust-bitcoin` types, which implements
    /// [`bitcoin::consensus::Decodable`] from Hex, `Vec<&u8>`.
    ///
    /// # Errors
    ///
    /// This function will return an error either from the HTTP client, or the
    /// [`bitcoin::consensus::Decodable`] deserialization.
    async fn get_response_hex<T: Decodable>(&self, url: &str) -> Result<T, Error>;

    /// Make an HTTP GET request to given URL, deserializing to `Option<T>`.
    ///
    /// It uses [`AsyncEsploraClient::get_response_hex`] internally.
    ///
    /// See [`AsyncEsploraClient::get_response_hex`] above for full
    /// documentation.
    async fn get_opt_response_hex<T: Decodable>(&self, url: &str) -> Result<Option<T>, Error>;

    /// Make an HTTP GET request to given URL, deserializing to `String`.
    ///
    /// It should be used when requesting Esplora endpoints that can return
    /// `String` formatted data that can be parsed downstream.
    ///
    /// # Errors
    ///
    /// This function will return an error either from the HTTP client.
    async fn get_response_text(&self, url: &str) -> Result<String, Error>;

    /// Make an HTTP GET request to given URL, deserializing to `Option<T>`.
    ///
    /// It uses [`AsyncEsploraClient::get_response_text`] internally.
    ///
    /// See [`AsyncEsploraClient::get_response_text`] above for full
    /// documentation.
    async fn get_opt_response_text(&self, url: &str) -> Result<Option<String>, Error>;
}

#[allow(unused_variables)]
#[async_trait::async_trait]
impl AsyncEsploraClient for Client {
    async fn get_response<T: Decodable>(&self, url: &str) -> Result<T, Error> {
        let response = self.get(url).send().await?;

        match response.status().is_success() {
            true => Ok(deserialize::<T>(&response.bytes().await?)?),
            false => Err(Error::HttpResponse {
                status: response.status().as_u16(),
                message: response.text().await?,
            }),
        }
    }

    async fn get_opt_response<T: Decodable>(&self, url: &str) -> Result<Option<T>, Error> {
        match self.get_response::<T>(url).await {
            Ok(res) => Ok(Some(res)),
            Err(Error::HttpResponse { status, message }) => match status {
                404 => Ok(None),
                _ => Err(Error::HttpResponse { status, message }),
            },
            Err(e) => Err(e),
        }
    }

    async fn get_response_json<T: serde::de::DeserializeOwned>(
        &self,
        url: &str,
    ) -> Result<T, Error> {
        let response = self.get(url).send().await?;

        match response.status().is_success() {
            // TODO: (@leonardo) this should not return an `Error::Reqwest` as it's failing due to
            // json deserialization !
            true => Ok(response.json::<T>().await.map_err(Error::Reqwest)?),
            false => Err(Error::HttpResponse {
                status: response.status().as_u16(),
                message: response.text().await?,
            }),
        }
    }

    async fn get_opt_response_json<T: serde::de::DeserializeOwned>(
        &self,
        url: &str,
    ) -> Result<Option<T>, Error> {
        match self.get_response_json(url).await {
            Ok(res) => Ok(Some(res)),
            Err(Error::HttpResponse { status, message }) => match status {
                404 => Ok(None),
                _ => Err(Error::HttpResponse { status, message }),
            },
            Err(e) => Err(e),
        }
    }

    async fn get_response_hex<T: Decodable>(&self, url: &str) -> Result<T, Error> {
        let response = self.get(url).send().await?;

        match response.status().is_success() {
            true => {
                let hex_str = response.text().await?;
                let hex_vec = Vec::from_hex(&hex_str)?;
                Ok(deserialize(&hex_vec)?)
            }
            false => Err(Error::HttpResponse {
                status: response.status().as_u16(),
                message: response.text().await?,
            }),
        }
    }

    async fn get_opt_response_hex<T: Decodable>(&self, url: &str) -> Result<Option<T>, Error> {
        match self.get_response_hex(url).await {
            Ok(res) => Ok(Some(res)),
            Err(Error::HttpResponse { status, message }) => match status {
                404 => Ok(None),
                _ => Err(Error::HttpResponse { status, message }),
            },
            Err(e) => Err(e),
        }
    }

    async fn get_response_text(&self, url: &str) -> Result<String, Error> {
        let response = self.get(url).send().await?;

        match response.status().is_success() {
            true => Ok(response.text().await?),
            false => Err(Error::HttpResponse {
                status: response.status().as_u16(),
                message: response.text().await?,
            }),
        }
    }

    async fn get_opt_response_text(&self, url: &str) -> Result<Option<String>, Error> {
        match self.get_response_text(url).await {
            Ok(s) => Ok(Some(s)),
            Err(Error::HttpResponse { status, message }) => match status {
                404 => Ok(None),
                _ => Err(Error::HttpResponse { status, message }),
            },
            Err(e) => Err(e),
        }
    }
}

#[derive(Debug, Clone)]
pub struct AsyncClient {
    /// The URL of the Esplora Server.
    url: String,
    /// The inner [`reqwest::Client`] to make HTTP requests.
    client: Client,
}

impl AsyncClient {
    /// Build an async client from a builder
    pub fn from_builder(builder: Builder) -> Result<Self, Error> {
        let mut client_builder = Client::builder();

        #[cfg(not(target_arch = "wasm32"))]
        if let Some(proxy) = &builder.proxy {
            client_builder = client_builder.proxy(reqwest::Proxy::all(proxy)?);
        }

        #[cfg(not(target_arch = "wasm32"))]
        if let Some(timeout) = builder.timeout {
            client_builder = client_builder.timeout(core::time::Duration::from_secs(timeout));
        }

        if !builder.headers.is_empty() {
            let mut headers = header::HeaderMap::new();
            for (k, v) in builder.headers {
                let header_name = header::HeaderName::from_lowercase(k.to_lowercase().as_bytes())
                    .map_err(|_| Error::InvalidHttpHeaderName(k))?;
                let header_value = header::HeaderValue::from_str(&v)
                    .map_err(|_| Error::InvalidHttpHeaderValue(v))?;
                headers.insert(header_name, header_value);
            }
            client_builder = client_builder.default_headers(headers);
        }

        Ok(Self::from_client(builder.base_url, client_builder.build()?))
    }

    /// Build an async client from the base url and [`Client`]
    pub fn from_client(url: String, client: Client) -> Self {
        AsyncClient { url, client }
    }

    /// Get a [`Transaction`] option given its [`Txid`]
    pub async fn get_tx(&self, txid: &Txid) -> Result<Option<Transaction>, Error> {
        self.client
            .get_opt_response(&format!("{}/tx/{txid}/raw", self.url))
            .await
    }

    /// Get a [`Transaction`] given its [`Txid`].
    pub async fn get_tx_no_opt(&self, txid: &Txid) -> Result<Transaction, Error> {
        match self.get_tx(txid).await {
            Ok(Some(tx)) => Ok(tx),
            Ok(None) => Err(Error::TransactionNotFound(*txid)),
            Err(e) => Err(e),
        }
    }

    /// Get a [`Txid`] of a transaction given its index in a block with a given
    /// hash.
    pub async fn get_txid_at_block_index(
        &self,
        block_hash: &BlockHash,
        index: usize,
    ) -> Result<Option<Txid>, Error> {
        match self
            .client
            .get_opt_response_text(&format!("{}/block/{block_hash}/txid/{index}", self.url))
            .await?
        {
            Some(s) => Ok(Some(Txid::from_str(&s).map_err(Error::HexToArray)?)),
            None => Ok(None),
        }
    }

    /// Get the status of a [`Transaction`] given its [`Txid`].
    pub async fn get_tx_status(&self, txid: &Txid) -> Result<TxStatus, Error> {
        self.client
            .get_response_json(&format!("{}/tx/{txid}/status", self.url))
            .await
    }

    /// Get transaction info given it's [`Txid`].
    pub async fn get_tx_info(&self, txid: &Txid) -> Result<Option<Tx>, Error> {
        self.client
            .get_opt_response_json(&format!("{}/tx/{txid}", self.url))
            .await
    }

    /// Get a [`BlockHeader`] given a particular block hash.
    pub async fn get_header_by_hash(&self, block_hash: &BlockHash) -> Result<BlockHeader, Error> {
        self.client
            .get_response_hex(&format!("{}/block/{block_hash}/header", self.url))
            .await
    }

    /// Get the [`BlockStatus`] given a particular [`BlockHash`].
    pub async fn get_block_status(&self, block_hash: &BlockHash) -> Result<BlockStatus, Error> {
        self.client
            .get_response_json(&format!("{}/block/{block_hash}/status", self.url))
            .await
    }

    /// Get a [`Block`] given a particular [`BlockHash`].
    pub async fn get_block_by_hash(&self, block_hash: &BlockHash) -> Result<Option<Block>, Error> {
        self.client
            .get_opt_response(&format!("{}/block/{block_hash}/raw", self.url))
            .await
    }

    /// Get a merkle inclusion proof for a [`Transaction`] with the given
    /// [`Txid`].
    pub async fn get_merkle_proof(&self, tx_hash: &Txid) -> Result<Option<MerkleProof>, Error> {
        self.client
            .get_opt_response_json(&format!("{}/tx/{tx_hash}/merkle-proof", self.url))
            .await
    }

    /// Get a [`MerkleBlock`] inclusion proof for a [`Transaction`] with the
    /// given [`Txid`].
    pub async fn get_merkle_block(&self, tx_hash: &Txid) -> Result<Option<MerkleBlock>, Error> {
        self.client
            .get_opt_response_hex(&format!("{}/tx/{tx_hash}/merkleblock-proof", self.url))
            .await
    }

    /// Get the spending status of an output given a [`Txid`] and the output
    /// index.
    pub async fn get_output_status(
        &self,
        txid: &Txid,
        index: u64,
    ) -> Result<Option<OutputStatus>, Error> {
        self.client
            .get_opt_response_json(&format!("{}/tx/{txid}/outspend/{index}", self.url))
            .await
    }

    /// Broadcast a [`Transaction`] to Esplora
    pub async fn broadcast(&self, transaction: &Transaction) -> Result<(), Error> {
        let resp = self
            .client
            .post(&format!("{}/tx", self.url))
            .body(serialize(transaction).to_lower_hex_string())
            .send()
            .await?;

        if resp.status().is_server_error() || resp.status().is_client_error() {
            Err(Error::HttpResponse {
                status: resp.status().as_u16(),
                message: resp.text().await?,
            })
        } else {
            Ok(())
        }
    }

    /// Get the current height of the blockchain tip
    pub async fn get_height(&self) -> Result<u32, Error> {
        self.client
            .get_response_text(&format!("{}/blocks/tip/height", self.url))
            .await
            .map(|height| u32::from_str(&height).map_err(Error::Parsing))?
    }

    /// Get the [`BlockHash`] of the current blockchain tip.
    pub async fn get_tip_hash(&self) -> Result<BlockHash, Error> {
        self.client
            .get_response_text(&format!("{}/blocks/tip/hash", self.url))
            .await
            .map(|block_hash| BlockHash::from_str(&block_hash).map_err(Error::HexToArray))?
    }

    /// Get the [`BlockHash`] of a specific block height
    pub async fn get_block_hash(&self, block_height: u32) -> Result<BlockHash, Error> {
        // FIXME: should this use a new `get_opt_response_str` instead ?
        self.client
            .get_response_text(&format!("{}/block-height/{}", self.url, block_height))
            .await
            .map(|block_hash| BlockHash::from_str(&block_hash).map_err(Error::HexToArray))?
    }

    /// Get confirmed transaction history for the specified address/scripthash,
    /// sorted with newest first. Returns 25 transactions per page.
    /// More can be requested by specifying the last txid seen by the previous
    /// query.
    pub async fn scripthash_txs(
        &self,
        script: &Script,
        last_seen: Option<Txid>,
    ) -> Result<Vec<Tx>, Error> {
        let script_hash = sha256::Hash::hash(script.as_bytes());
        let url = match last_seen {
            Some(last_seen) => format!(
                "{}/scripthash/{:x}/txs/chain/{}",
                self.url, script_hash, last_seen
            ),
            None => format!("{}/scripthash/{:x}/txs", self.url, script_hash),
        };

        self.client.get_response_json(&url).await
    }

    /// Get an map where the key is the confirmation target (in number of
    /// blocks) and the value is the estimated feerate (in sat/vB).
    pub async fn get_fee_estimates(&self) -> Result<HashMap<u16, f64>, Error> {
        self.client
            .get_response_json(&format!("{}/fee-estimates", self.url))
            .await
    }

    /// Gets some recent block summaries starting at the tip or at `height` if
    /// provided.
    ///
    /// The maximum number of summaries returned depends on the backend itself:
    /// esplora returns `10` while [mempool.space](https://mempool.space/docs/api) returns `15`.
    pub async fn get_blocks(&self, height: Option<u32>) -> Result<Vec<BlockSummary>, Error> {
        let url = match height {
            Some(height) => format!("{}/blocks/{height}", self.url),
            None => format!("{}/blocks", self.url),
        };
        self.client.get_response_json(&url).await
    }

    /// Get the underlying base URL.
    pub fn url(&self) -> &str {
        &self.url
    }

    /// Get the underlying [`Client`].
    pub fn client(&self) -> &Client {
        &self.client
    }
}
