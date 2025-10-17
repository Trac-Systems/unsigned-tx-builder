Creates an unsigned tx for Bitcoin to send a single, specific UTXO to a selected destination.

How-to use:

- adjust config in index.js
- use prevTxId, vout and inputSat from a utxo you want to spend
- set destAddr for the receiver
- set minFeeRate (will be used from inputSat)
- execute: node index.js
- review and sign the resulting unsigned tx