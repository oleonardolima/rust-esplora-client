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

use reqwest::{header, Client, StatusCode};

use crate::{BlockStatus, BlockSummary, Builder, Error, MerkleProof, OutputStatus, Tx, TxStatus};

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

    /// .
    ///
    /// # Errors
    ///
    /// This function will return an error if .
    async fn get_opt_response<T: Decodable>(&self, path: &str) -> Result<Option<T>, Error> {
        let url = format!("{}{}", self.url, path);
        let response = self.client.get(url).send().await?;

        if response.status().eq(&StatusCode::NOT_FOUND) {
            return Ok(None);
        };

        match response.status().is_success() {
            true => Ok(Some(deserialize::<T>(&response.bytes().await?)?)),
            false => Err(Error::HttpResponse {
                status: response.status().as_u16(),
                message: response.text().await?,
            }),
        }
    }

    /// .
    ///
    /// # Errors
    ///
    /// This function will return an error if .
    async fn get_opt_response_txid(&self, path: &str) -> Result<Option<Txid>, Error> {
        let url = format!("{}{}", self.url, path);
        let response = self.client.get(url).send().await?;

        if response.status().eq(&StatusCode::NOT_FOUND) {
            return Ok(None);
        };

        match response.status().is_success() {
            true => {
                let txid = Txid::from_str(&response.text().await?)?;
                Ok(Some(txid))
            }
            false => Err(Error::HttpResponse {
                status: response.status().as_u16(),
                message: response.text().await?,
            }),
        }
    }

    /// .
    ///
    /// # Errors
    ///
    /// This function will return an error if .
    async fn get_response_json<T: serde::de::DeserializeOwned>(
        &self,
        path: &str,
    ) -> Result<T, Error> {
        let url = format!("{}{}", self.url, path);
        let response = self.client.get(url).send().await?;

        match response.status().is_success() {
            // TODO: (@leonardo) this should not return an `Error::Reqwest` as it's failing due to json deserialization !
            true => Ok(response.json::<T>().await.map_err(Error::Reqwest)?),
            false => Err(Error::HttpResponse {
                status: response.status().as_u16(),
                message: response.text().await?,
            }),
        }
    }

    /// .
    ///
    /// # Errors
    ///
    /// This function will return an error if .
    async fn get_opt_response_json<'a, T: serde::de::DeserializeOwned>(
        &self,
        path: &str,
    ) -> Result<Option<T>, Error> {
        let url = format!("{}{}", self.url, path);
        let response = self.client.get(url).send().await?;

        if response.status().eq(&StatusCode::NOT_FOUND) {
            return Ok(None);
        };

        match response.status().is_success() {
            // TODO: (@leonardo) this should not return an `Error::Reqwest` as it's failing due to json deserialization !
            true => Ok(Some(response.json::<T>().await.map_err(Error::Reqwest)?)),
            false => Err(Error::HttpResponse {
                status: response.status().as_u16(),
                message: response.text().await?,
            }),
        }
    }

    async fn get_response_hex<T: Decodable>(&self, path: &str) -> Result<T, Error> {
        let url = format!("{}{}", self.url, path);
        let response = self.client.get(url).send().await?;

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

    async fn get_opt_response_hex<T: Decodable>(&self, path: &str) -> Result<Option<T>, Error> {
        let url = format!("{}{}", self.url, path);
        let response = self.client.get(url).send().await?;

        match response.status().is_success() {
            true => {
                let hex_str = response.text().await?;
                let hex_vec = Vec::from_hex(&hex_str)?;
                Ok(Some(deserialize(&hex_vec)?))
            }
            false => Err(Error::HttpResponse {
                status: response.status().as_u16(),
                message: response.text().await?,
            }),
        }
    }

    async fn get_response_str(&self, path: &str) -> Result<String, Error> {
        let url = format!("{}{}", self.url, path);
        let response = self.client.get(url).send().await?;

        match response.status().is_success() {
            true => Ok(response.text().await?),
            false => Err(Error::HttpResponse {
                status: response.status().as_u16(),
                message: response.text().await?,
            }),
        }
    }

    /// Get a [`Transaction`] option given its [`Txid`]
    pub async fn get_tx(&self, txid: &Txid) -> Result<Option<Transaction>, Error> {
        self.get_opt_response(&format!("/tx/{txid}/raw")).await
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
        self.get_opt_response_txid(&format!("/block/{block_hash}/txid/{index}"))
            .await
    }

    /// Get the status of a [`Transaction`] given its [`Txid`].
    pub async fn get_tx_status(&self, txid: &Txid) -> Result<TxStatus, Error> {
        self.get_response_json(&format!("/tx/{txid}/status")).await
    }

    /// Get transaction info given it's [`Txid`].
    pub async fn get_tx_info(&self, txid: &Txid) -> Result<Option<Tx>, Error> {
        self.get_opt_response_json(&format!("/tx/{txid}")).await
    }

    /// Get a [`BlockHeader`] given a particular block hash.
    pub async fn get_header_by_hash(&self, block_hash: &BlockHash) -> Result<BlockHeader, Error> {
        self.get_response_hex(&format!("/block/{block_hash}/header"))
            .await
    }

    /// Get the [`BlockStatus`] given a particular [`BlockHash`].
    pub async fn get_block_status(&self, block_hash: &BlockHash) -> Result<BlockStatus, Error> {
        self.get_response_json(&format!("/block/{block_hash}/status"))
            .await
    }

    /// Get a [`Block`] given a particular [`BlockHash`].
    pub async fn get_block_by_hash(&self, block_hash: &BlockHash) -> Result<Option<Block>, Error> {
        self.get_opt_response(&format!("/block/{block_hash}/raw"))
            .await
    }

    /// Get a merkle inclusion proof for a [`Transaction`] with the given
    /// [`Txid`].
    pub async fn get_merkle_proof(&self, tx_hash: &Txid) -> Result<Option<MerkleProof>, Error> {
        self.get_opt_response_json(&format!("/tx/{tx_hash}/merkle-proof"))
            .await
    }

    /// Get a [`MerkleBlock`] inclusion proof for a [`Transaction`] with the
    /// given [`Txid`].
    pub async fn get_merkle_block(&self, tx_hash: &Txid) -> Result<Option<MerkleBlock>, Error> {
        self.get_opt_response_hex(&format!("/tx/{tx_hash}/merkleblock-proof"))
            .await
    }

    /// Get the spending status of an output given a [`Txid`] and the output
    /// index.
    pub async fn get_output_status(
        &self,
        txid: &Txid,
        index: u64,
    ) -> Result<Option<OutputStatus>, Error> {
        self.get_opt_response_json(&format!("/tx/{txid}/outspend/{index}"))
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
        self.get_response_str("/blocks/tip/height")
            .await
            .map(|height| u32::from_str(&height).map_err(Error::Parsing))?
    }

    /// Get the [`BlockHash`] of the current blockchain tip.
    pub async fn get_tip_hash(&self) -> Result<BlockHash, Error> {
        self.get_response_str("/blocks/tip/hash")
            .await
            .map(|block_hash| BlockHash::from_str(&block_hash).map_err(Error::HexToArray))?
    }

    /// Get the [`BlockHash`] of a specific block height
    pub async fn get_block_hash(&self, block_height: u32) -> Result<BlockHash, Error> {
        // FIXME: should this use a new `get_opt_response_str` instead ?
        self.get_response_str(&format!("/block-height/{block_height}"))
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
        let path = match last_seen {
            Some(last_seen) => format!("/scripthash/{:x}/txs/chain/{}", script_hash, last_seen),
            None => format!("/scripthash/{:x}/txs", script_hash),
        };

        self.get_response_json(&path).await
    }

    /// Get an map where the key is the confirmation target (in number of
    /// blocks) and the value is the estimated feerate (in sat/vB).
    pub async fn get_fee_estimates(&self) -> Result<HashMap<u16, f64>, Error> {
        self.get_response_json("/fee-estimates").await
    }

    /// Gets some recent block summaries starting at the tip or at `height` if
    /// provided.
    ///
    /// The maximum number of summaries returned depends on the backend itself:
    /// esplora returns `10` while [mempool.space](https://mempool.space/docs/api) returns `15`.
    pub async fn get_blocks(&self, height: Option<u32>) -> Result<Vec<BlockSummary>, Error> {
        let path = match height {
            Some(height) => format!("/blocks/{height}"),
            None => "/blocks".to_string(),
        };
        self.get_response_json(&path).await
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
