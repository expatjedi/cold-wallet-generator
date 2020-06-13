### Lightweight, open-source, universal paper wallet generator

#### Description
Using third-party services to generate paper wallets should be avoided without proper code auditing by independent entities.   

Unnecessary codes and poorly written libraries are often used, creating a huge security risk for users. Some services advertise that their generator works offline, and thus its users are immune to private key theft. However, there is still a possibility that an offline paper wallet generator creates keys deterministically without ever needing to communicate this information in any way.   

For this reason, I wouldn't trust any random websites offering offline paper wallet generators without proper investigation.  
On the other hand, my paper wallet contains no bloat but only the essentials.   

Feel free to use it.

#### Features
* Simple, efficient, secure
* Client-side, works offline
* Constant updates
* Transparent, easy to audit
* Ink-friendly
* Integrity of files validated; meaning files have not been tampered with (see below)
* More than 510 cryptocurrencies supported

#### Instructions
* Use this generator offline for maximum security.
* Generate and print your wallet. Keep it in a secure location.
* Deposit funds to your paper wallet by sending them to the public address.
* Private key is used to spend funds. Do not share it!

#### Tips appreciated!  
**BTC**: 3MEmomSUDWqWmEtRNoakSxF9ZgZuxn8tJj    

#
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
	* [SHA-256] 11e0a812af465183a588e62dc73b14bcb06fd33797740616e3b1a07922e9bc6a
* [stellar-base.js](https://github.com/stellar/bower-js-stellar-base) v0.8.2 (Official Stellar API)
	* [SHA-256] AD6BE647329F8159B6BB2F7F6E7CC8DE9B39B092951858EBB3F8ED5A1C66C8F4
* [bitcore-lib-zcash.js](https://github.com/bitmex/zcash-bitcore-lib)
	* [SHA-256] 621ad3c644508da28ac671c432a78de1d3b0f51a24edbd065bdb2c0e8f2f154c
* [qrcode.js](https://github.com/davidshimjs/qrcodejs)
	* [SHA-256] 3ee72de9f69c668f9567363a9358df955960bae9000d9ebd66414670f88e8735
