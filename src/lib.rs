use rust_crypto_lib_base::get_limit_order_hash;
use rust_crypto_lib_base::get_order_hash;
use rust_crypto_lib_base::get_private_key_from_eth_signature;
use rust_crypto_lib_base::get_transfer_hash;
use rust_crypto_lib_base::get_withdraw_and_stake_eip712_hash;
use rust_crypto_lib_base::get_withdraw_and_stake_hash;
use rust_crypto_lib_base::get_withdrawal_hash;
use rust_crypto_lib_base::sign_message as rust_sign;

use starknet_crypto::Felt;
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub struct StarkSignature {
    r: String,
    s: String,
    v: String,
}

#[wasm_bindgen]
impl StarkSignature {
    #[wasm_bindgen(constructor)]
    pub fn new(r: String, s: String, v: String) -> StarkSignature {
        StarkSignature { r, s, v }
    }

    #[wasm_bindgen(getter)]
    pub fn r(&self) -> String {
        self.r.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn s(&self) -> String {
        self.s.clone()
    }
    #[wasm_bindgen(getter)]
    pub fn v(&self) -> String {
        self.v.clone()
    }
}

#[wasm_bindgen]

pub fn generate_private_key_from_eth_signature(sig: &str) -> String {
    return get_private_key_from_eth_signature(sig)
        .unwrap()
        .to_hex_string();
}

#[wasm_bindgen]
pub fn sign_message(private_key_hex: &str, message_hex: &str) -> StarkSignature {
    let private_key = Felt::from_hex(private_key_hex).unwrap();
    let message = Felt::from_hex(message_hex).unwrap();
    return rust_sign(&message, &private_key)
        .map(|sig| {
            StarkSignature::new(
                sig.r.to_hex_string(),
                sig.s.to_hex_string(),
                sig.v.to_hex_string(),
            )
        })
        .unwrap();
}

#[wasm_bindgen]
pub fn get_withdraw_msg(
    recipient_hex: String,
    position_id: String,
    collateral_id_hex: String,
    amount: String,
    expiration: String,
    salt: String,
    user_public_key_hex: String,
    domain_name: String,
    domain_version: String,
    domain_chain_id: String,
    domain_revision: String,
) -> String {
    return get_withdrawal_hash(
        recipient_hex,
        position_id,
        collateral_id_hex,
        amount,
        expiration,
        salt,
        user_public_key_hex,
        domain_name,
        domain_version,
        domain_chain_id,
        domain_revision,
    )
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
    return get_transfer_hash(
        recipient_position_id.to_owned(),
        sender_position_id.to_owned(),
        collateral_id_hex.to_owned(),
        amount.to_owned(),
        expiration.to_owned(),
        salt.to_owned(),
        user_public_key_hex.to_owned(),
        domain_name.to_owned(),
        domain_version.to_owned(),
        domain_chain_id.to_owned(),
        domain_revision.to_owned(),
    )
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
    return get_order_hash(
        position_id.to_owned(),
        base_asset_id_hex.to_owned(),
        base_amount.to_owned(),
        quote_asset_id_hex.to_owned(),
        quote_amount.to_owned(),
        fee_asset_id_hex.to_owned(),
        fee_amount.to_owned(),
        expiration.to_owned(),
        salt.to_owned(),
        user_public_key_hex.to_owned(),
        domain_name.to_owned(),
        domain_version.to_owned(),
        domain_chain_id.to_owned(),
        domain_revision.to_owned(),
    )
    .unwrap()
    .to_hex_string();
}

#[wasm_bindgen]
pub fn get_limit_order_msg(
    source_position_id: &str,
    receive_position_id: &str,
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
    return get_limit_order_hash(
        source_position_id.to_owned(),
        receive_position_id.to_owned(),
        base_asset_id_hex.to_owned(),
        base_amount.to_owned(),
        quote_asset_id_hex.to_owned(),
        quote_amount.to_owned(),
        fee_asset_id_hex.to_owned(),
        fee_amount.to_owned(),
        expiration.to_owned(),
        salt.to_owned(),
        user_public_key_hex.to_owned(),
        domain_name.to_owned(),
        domain_version.to_owned(),
        domain_chain_id.to_owned(),
        domain_revision.to_owned(),
    )
    .unwrap()
    .to_hex_string();
}

#[wasm_bindgen]
pub fn get_withdraw_and_stake_msg(
    position_id: &str,
    collateral_id_hex: &str,
    amount: &str,
    vault_hex: &str,
    beneficiary_hex: &str,
    expiration: &str,
    salt: &str,
    user_public_key_hex: &str,
    domain_name: &str,
    domain_version: &str,
    domain_chain_id: &str,
    domain_revision: &str,
) -> String {
    return get_withdraw_and_stake_hash(
        position_id.to_owned(),
        collateral_id_hex.to_owned(),
        amount.to_owned(),
        vault_hex.to_owned(),
        beneficiary_hex.to_owned(),
        expiration.to_owned(),
        salt.to_owned(),
        user_public_key_hex.to_owned(),
        domain_name.to_owned(),
        domain_version.to_owned(),
        domain_chain_id.to_owned(),
        domain_revision.to_owned(),
    )
    .unwrap()
    .to_hex_string();
}

/// The `eth_signTypedData_v4` JSON document the withdraw-and-stake beneficiary's EVM wallet signs. Takes the
/// same inputs as `get_withdraw_and_stake_msg`, plus the EVM chain id and the settlement contract.
#[wasm_bindgen]
pub fn get_withdraw_and_stake_eip712_typed_data(
    position_id: &str,
    collateral_id_hex: &str,
    amount: &str,
    vault_hex: &str,
    beneficiary_hex: &str,
    expiration: &str,
    salt: &str,
    evm_chain_id: &str,
    verifying_contract_hex: &str,
) -> String {
    return rust_crypto_lib_base::get_withdraw_and_stake_eip712_typed_data(
        position_id.to_owned(),
        collateral_id_hex.to_owned(),
        amount.to_owned(),
        vault_hex.to_owned(),
        beneficiary_hex.to_owned(),
        expiration.to_owned(),
        salt.to_owned(),
        evm_chain_id.to_owned(),
        verifying_contract_hex.to_owned(),
    )
    .unwrap();
}

/// The 32-byte EIP-712 digest (hex) of the document `get_withdraw_and_stake_eip712_typed_data` returns.
#[wasm_bindgen]
pub fn get_withdraw_and_stake_eip712_msg(
    position_id: &str,
    collateral_id_hex: &str,
    amount: &str,
    vault_hex: &str,
    beneficiary_hex: &str,
    expiration: &str,
    salt: &str,
    evm_chain_id: &str,
    verifying_contract_hex: &str,
) -> String {
    return get_withdraw_and_stake_eip712_hash(
        position_id.to_owned(),
        collateral_id_hex.to_owned(),
        amount.to_owned(),
        vault_hex.to_owned(),
        beneficiary_hex.to_owned(),
        expiration.to_owned(),
        salt.to_owned(),
        evm_chain_id.to_owned(),
        verifying_contract_hex.to_owned(),
    )
    .unwrap();
}

#[cfg(test)]
mod tests {
    use super::*;
    use wasm_bindgen_test::*;

    #[wasm_bindgen_test]
    fn test_signature_call() {
        let sig = "0x9ef64d5936681edf44b4a7ad713f3bc24065d4039562af03fccf6a08d6996eab367df11439169b417b6a6d8ce81d409edb022597ce193916757c7d5d9cbf97301c";
        let private_key_hex = generate_private_key_from_eth_signature(sig);
        let resp = sign_message(&*private_key_hex, "0x12345");
        assert_eq!(
            resp.r(),
            "0x6490498b85b4eedb02416848deb856ecbcdd053d245ceb90281c30b66209ce5"
        );
    }

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

        let expected =
            Felt::from_hex("0x56c7b21d13b79a33d7700dda20e22246c25e89818249504148174f527fc3f8f")
                .unwrap();
        assert_eq!(transfer_msg, expected.to_hex_string());
    }

    // signed_messages.cairo in starknet-perpetual-private, perp-core, starkex-client and
    // rust-crypto-lib-base pin the same SN_MAIN message hash.
    #[wasm_bindgen_test]
    fn test_get_withdraw_and_stake_msg() {
        let msg = get_withdraw_and_stake_msg(
            "1",
            "0x2",
            "3",
            "0x5fbdb2315678afecb367f032d93f642f64180aa3",
            "0x70997970c51812dc3a010c7d01b50e0d17dc79c8",
            "6",
            "7",
            "0x00341db4194da6cdeff282feebca99387e754f7ab81b676262e64e194f342a87",
            "Perpetuals",
            "v0",
            "SN_MAIN",
            "1",
        );

        let expected =
            Felt::from_hex("0x0520cb61ba9d79eb785abd3085b97a10fab05b4ee9b40133543cce1f9f7ac662")
                .unwrap();
        assert_eq!(msg, expected.to_hex_string());
    }

    // starkex-client's WithdrawAndStakeTest and zkp's perp-core pin this digest, from Foundry's `cast`.
    #[wasm_bindgen_test]
    fn test_get_withdraw_and_stake_eip712_msg() {
        let msg = get_withdraw_and_stake_eip712_msg(
            "1",
            "0x2",
            "3",
            "0x5fbdb2315678afecb367f032d93f642f64180aa3",
            "0x70997970c51812dc3a010c7d01b50e0d17dc79c8",
            "6",
            "7",
            "31337",
            "0x1111111111111111111111111111111111111111",
        );

        assert_eq!(
            msg,
            "0x8a90600e06caea19adf9b0c3217116d00026fea0b525e368fc1533243e83c658"
        );
    }

    #[wasm_bindgen_test]
    fn test_get_withdraw_and_stake_eip712_typed_data() {
        let typed_data = get_withdraw_and_stake_eip712_typed_data(
            "1",
            "0x2",
            "3",
            "0x5fbdb2315678afecb367f032d93f642f64180aa3",
            "0x70997970c51812dc3a010c7d01b50e0d17dc79c8",
            "6",
            "7",
            "31337",
            "0x1111111111111111111111111111111111111111",
        );

        assert!(typed_data.contains(r#""primaryType":"WithdrawAndStake""#));
        assert!(
            typed_data.contains(r#""beneficiary":"0x70997970c51812dc3a010c7d01b50e0d17dc79c8""#)
        );
        assert!(typed_data.contains(r#""chainId":31337"#));
    }
}
