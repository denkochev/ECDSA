# ECDSA signature with SHA256 on secp256k1 
Naive implementation of ECDSA signature algorithm on secp256k1 elliptic curve with sha256 hash function.

## Installation
To use this wrapper you have to install bitcoin `GO` implementation blockchain from: https://github.com/btcsuite/btcd/tree/master/btcec and secp256k1/v4 dir.

Use this command if your local environment doesn't have the required packages.
```
go get github.com/btcsuite/btcd@master
go get github.com/decred/dcrd/dcrec/secp256k1/v4
```

## Usage
Package includes two structures: for publicKey (ElipticPoint) and for signature (Signature).

### How to sign message:
1. Generate key pair using ecdsa.KeyGen() func.
```go
privateKey, publicKey := ecdsa.KeyGen()
```
2. Call function ecdsa.SIG.

You can sign any []byte includes your PC files. Let's sign text message.
```go
message := "I'm a Fullstack developer *_*"
sig := ecdsa.SIG([]byte(message), privateKey)
```
SIG returns `Signature` object with r and s as BigInts.

### How to verify signature
1. To verify signature you have to know message itself, public key and signature.
```go
ecdsa.Verify([]byte(message), publicKey, sig)
```
This function returns boolean value, true if signature valid, false in any other situations. 
### Parsers

You can treat yours public key and signature as hex string.
```go
hexSignature := sig.ToHex()
pkHex := publicKey.ToHex()
```
To use them in sign/ver algos you have to set objects from hex.
```go
// for sig
newSignature := ecdsa.Signature{}
newSignature.SetFromHex(hexSignature)

// for pk
pkFromHex := ecdsa.ElipticPoint{}
pkFromHex.SetFromHex(pkHex)
```