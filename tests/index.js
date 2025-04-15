import * as wasm from "stark-crypto-wrapper-wasm";
let result = wasm.generate_private_key_from_eth_signature("0x9ef64d5936681edf44b4a7ad713f3bc24065d4039562af03fccf6a08d6996eab367df11439169b417b6a6d8ce81d409edb022597ce193916757c7d5d9cbf97301c")
document.getElementById("private_key").innerText = result;