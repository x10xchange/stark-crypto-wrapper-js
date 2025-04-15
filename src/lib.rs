use rust_crypto_lib_base::{
    get_private_key_from_eth_signature,
    starknet_messages::{AssetId, OffChainMessage, Order, PositionId, StarknetDomain, Timestamp},
};

use starknet_crypto::Felt;
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub fn generate_private_key_from_eth_signature(name: &str) -> String {
    return get_private_key_from_eth_signature(name)
        .unwrap()
        .to_hex_string();
}

#[wasm_bindgen]
pub fn get_order_msg(
    position_id: &str,
    base_asset_id_hex: &str,
    base_amount: &str,
    quote_asset_id_hex: &str,
    quote_amount: &str,
    fee_asset_id_hex: &str,
    fee_amount: &str,
    expiration: &str,
    salt: &str,
    user_public_key_hex: &str,

    domain_name: &str,
    domain_version: &str,
    domain_chain_id: &str,
    domain_revision: &str,
) -> String {
    //hex fields
    let base_asset_id = Felt::from_hex(&base_asset_id_hex).unwrap();
    let quote_asset_id = Felt::from_hex(&quote_asset_id_hex).unwrap();
    let fee_asset_id = Felt::from_hex(&fee_asset_id_hex).unwrap();
    let user_key = Felt::from_hex(&user_public_key_hex).unwrap();

    //decimal fields
    let position_id = u32::from_str_radix(&position_id, 10).unwrap();
    let base_amount = i64::from_str_radix(&base_amount, 10).unwrap();
    let quote_amount = i64::from_str_radix(&quote_amount, 10).unwrap();
    let fee_amount = u64::from_str_radix(&fee_amount, 10).unwrap();
    let expiration = u64::from_str_radix(&expiration, 10).unwrap();
    let salt = u64::from_str_radix(&salt, 10).unwrap();

    let order = Order {
        position_id: PositionId { value: position_id },
        base_asset_id: AssetId {
            value: base_asset_id,
        },
        base_amount: base_amount,
        quote_asset_id: AssetId {
            value: quote_asset_id,
        },
        quote_amount: quote_amount,
        fee_asset_id: AssetId {
            value: fee_asset_id,
        },
        fee_amount: fee_amount,
        expiration: Timestamp {
            seconds: expiration,
        },
        salt: salt.try_into().unwrap(),
    };
    let domain = StarknetDomain {
        name: domain_name.to_owned(),
        version: domain_version.to_owned(),
        chain_id: domain_chain_id.to_owned(),
        revision: domain_revision.to_owned(),
    };
    let message = order.message_hash(&domain, user_key).unwrap();

    return message.to_hex_string();
}
