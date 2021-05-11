### Lightweight, open-source, universal paper wallet generator

#### Features
* Simple, efficient, secure
* Client-side, works offline
* Constant updates
* Transparent, easy to audit
* Ink-friendly
* Integrity of files validated; meaning files have not been tampered with (see below)
* More than 510 cryptocurrencies supported

#### Instructions

Always use the paper wallet generator offline. Go to the paper wallet's GitHub page, download the latest release on a usb drive, open the zip file in a drive on a computer without an internet connection. After producing enough wallets, print out and clear the printer memory. Restarting the printer will reset the device and clear its memory of any active print jobs. For this, turn off the printer and unplug it from the power socket. Leave it for a minute and then plug the printer into the power socket. This will fully clear out the power of the memory and erase it completely.

**Public Address** is for to get paid. You can share with as many people as you want, even add it in to your forum signature. However, I recommend using only 1 address for each payment. Think of it as using a burner phone.

**Private key** is for accessing and spending your coins so don't share it with anyone under any circumstances. Even with your closest relatives! Once your private key is handed over to someone else, they can spend the coins at the address that the key is connected to. That's why I recommend using only 1 address for each payment. You will know the safest place for your wallets to be loaded, but my advice is rental bank safes. You can apply a coating on paper against abrasion over time.


#### Integrity validation
* [bitcoinjs-lib.js](https://github.com/bitcoinjs/bitcoinjs-lib) v3.3.2
	* [SHA-256] 34fb2141b70f690a8eb9fa75e703e99b39f8538201250115fc895343b7739708
* [bitcoincash-0.1.10.js](https://github.com/bitcoincashjs/bitcoincashjs)
	* [SHA-256] 0f98a457e504ffa94a0cd01488cb4dd94327a5fc655950de5a1e0b739faba252
* [web3-eth-accounts.js](https://github.com/ethereum/web3.js) (Official Ethereum API)
	* [SHA-256] 486fcaf21777aded0550ff96001f146855430904d7da2e3858a07835edd53212
* [ripple-0.22.js](https://github.com/ripple/ripple-lib/releases) (Official Ripple API)
	* [SHA-256] AB98026FABE296BD938297C48CB58E01DFDBE90F3C66C9617D6A3E1EFD4C6B93
* [lodash.js](https://github.com/lodash/lodash) (Ripple API dependency)
	* [SHA-256] 4c04561befdf653aef017a42ac5addf68ea943cdfca6bdee5ce04e04e8139f54
* [stellar-base.js](https://github.com/stellar/bower-js-stellar-base) v0.8.2 (Official Stellar API)
	* [SHA-256] AD6BE647329F8159B6BB2F7F6E7CC8DE9B39B092951858EBB3F8ED5A1C66C8F4
* [bitcore-lib-zcash.js](https://github.com/bitmex/zcash-bitcore-lib)
	* [SHA-256] 621ad3c644508da28ac671c432a78de1d3b0f51a24edbd065bdb2c0e8f2f154c
* [monero.js](https://github.com/monero-project/monero) (Official Monero API)
	* [SHA-256] 8542b18b60ce05c69e69be0ed42aabbceca00bf26cf6f23930e8426a0428f726
* [qrcode.js](https://github.com/davidshimjs/qrcodejs)
	* [SHA-256] 3ee72de9f69c668f9567363a9358df955960bae9000d9ebd66414670f88e8735
