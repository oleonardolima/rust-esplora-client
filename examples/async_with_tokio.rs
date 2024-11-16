use std::str::FromStr;

use bitcoin::BlockHash;
use esplora_client::Builder;

#[tokio::main]
async fn main() {
    let builder = Builder::new("https://blockstream.info/api");

    let async_client = builder.build_async().unwrap();

    let block_hash =
        BlockHash::from_str("000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f")
            .unwrap();

    let block = async_client
        .get_block_by_hash(&block_hash)
        .await
        .unwrap()
        .unwrap();

    println!("Genesis Block:\n{:?}", block);
}
