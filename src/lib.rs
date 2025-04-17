use rust_crypto_lib_base::get_private_key_from_eth_signature;
use rust_crypto_lib_base::starknet_messages::AssetId;
use rust_crypto_lib_base::starknet_messages::OffChainMessage;
use rust_crypto_lib_base::starknet_messages::Order;
use rust_crypto_lib_base::starknet_messages::PositionId;
use rust_crypto_lib_base::starknet_messages::StarknetDomain;
use rust_crypto_lib_base::starknet_messages::Timestamp;
use rust_crypto_lib_base::starknet_messages::TransferArgs;

use starknet_crypto::Felt;
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub fn generate_private_key_from_eth_signature(sig: &str) -> String {
    return get_private_key_from_eth_signature(sig)
        .unwrap()
        .to_hex_string();
}

#[wasm_bindgen]
pub fn get_transfer_msg(
    recipient_position_id: &str,
    sender_position_id: &str,
    collateral_id_hex: &str,
    amount: &str,
    expiration: &str,
    salt: &str,
    user_public_key_hex: &str,

    domain_name: &str,
    domain_version: &str,
    domain_chain_id: &str,
    domain_revision: &str,
) -> String {
    // hex fields
    let collateral_id = Felt::from_hex(&collateral_id_hex).unwrap();
    let user_key = Felt::from_hex(&user_public_key_hex).unwrap();

    // decimal fields
    let recipient = u32::from_str_radix(&recipient_position_id, 10).unwrap();
    let position_id = u32::from_str_radix(&sender_position_id, 10).unwrap();
    let amount = u64::from_str_radix(&amount, 10).unwrap();
    let expiration = u64::from_str_radix(&expiration, 10).unwrap();
    let salt = Felt::from_dec_str(&salt).unwrap();

    let transfer_args = TransferArgs {
        recipient: PositionId { value: recipient },
        position_id: PositionId { value: position_id },
        collateral_id: AssetId {
            value: collateral_id,
        },
        amount,
        expiration: Timestamp {
            seconds: expiration,
        },
        salt,
    };
    let domain = StarknetDomain {
        name: domain_name.to_string(),
        version: domain_version.to_string(),
        chain_id: domain_chain_id.to_string(),
        revision: domain_revision.to_string(),
    };
    let message = transfer_args.message_hash(&domain, user_key).unwrap();
    return message.to_hex_string();
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

#[cfg(test)]
mod tests {
    use super::*;
    use wasm_bindgen_test::*;

    #[wasm_bindgen_test]
    fn test_generate_private_key_from_eth_signature() {
        let sig = "0x9ef64d5936681edf44b4a7ad713f3bc24065d4039562af03fccf6a08d6996eab367df11439169b417b6a6d8ce81d409edb022597ce193916757c7d5d9cbf97301c";
        let private_key = generate_private_key_from_eth_signature(sig);
        let expected_private = Felt::from_dec_str(
            "3554363360756768076148116215296798451844584215587910826843139626172125285444",
        )
        .unwrap();
        assert_eq!(private_key, expected_private.to_hex_string());
    }

    #[wasm_bindgen_test]
    fn test_get_transfer_msg() {
        let user_key = Felt::from_dec_str(
            "2629686405885377265612250192330550814166101744721025672593857097107510831364",
        )
        .unwrap();

        let recipient_position_id = "1";
        let sender_position_id = "2";
        let collateral_id_hex = "0x3";
        let amount = "4";
        let expiration = "5";
        let salt = "6";
        let user_public_key_hex = user_key.to_hex_string();
        let domain_name = "Perpetuals";
        let domain_version = "v0";
        let domain_chain_id = "SN_SEPOLIA";
        let domain_revision = "1";

        let transfer_msg = get_transfer_msg(
            recipient_position_id,
            sender_position_id,
            collateral_id_hex,
            amount,
            expiration,
            salt,
            &*user_public_key_hex,
            domain_name,
            domain_version,
            domain_chain_id,
            domain_revision,
        );

        let expected = Felt::from_dec_str(
            "3466709383481810859947861276094399756712395853968834582933311835633294184917",
        )
        .unwrap();
        assert_eq!(transfer_msg, expected.to_hex_string());
    }
}
