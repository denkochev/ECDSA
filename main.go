package main

import (
	"ecdsa/ecdsa"
	"fmt"
)

func main() {
	// 1. Generate key pair
	privateKey, publicKey := ecdsa.KeyGen()

	message := "I'm a Fullstack developer *_*"

	// 2. Sign the message with privateKey
	sig := ecdsa.SIG([]byte(message), privateKey)
	// sig is a struct with r and s bigInt values

	// 3. We can print sign in hex format
	fmt.Println("3 =============================================================")
	sig.PrintHex()

	// 4. To verify signature we should use message, publicKey and sig struct (r and s bigInt values)
	fmt.Println("4 =============================================================")
	fmt.Println("Verification -> ", ecdsa.Verify([]byte(message), publicKey, sig))

	// 5. We can get our signature as hex string
	hexSignature := sig.ToHex()
	fmt.Println("5 =============================================================")
	fmt.Println("signature in hex is -> ", hexSignature)

	// 6. We can also create signature struct from string hex.
	newSignature := ecdsa.Signature{}
	newSignature.SetFromHex(hexSignature)

	fmt.Println("6 =============================================================")
	fmt.Println("Verification for hex signature -> ", ecdsa.Verify([]byte(message), publicKey, newSignature))

	// Lets change symbol from signature and try to verify it
	newInvalidHex := hexSignature[:127] + "0"
	if newInvalidHex == hexSignature {
		newInvalidHex = hexSignature[:127] + "1"
	}

	fakeSig := ecdsa.Signature{}
	fakeSig.SetFromHex(newInvalidHex)
	fmt.Println("===================TEST-WITH-INVALID-HEX===================")
	fmt.Println("Verify fake hex -> ", ecdsa.Verify([]byte(message), publicKey, fakeSig))

	// You can also get your publickKey as a hex string
	pkHex := publicKey.ToHex()
	fmt.Println("===================PUBLIC-KEY-AS-HEX=======================")

	pkFromHex := ecdsa.ElipticPoint{}
	pkFromHex.SetFromHex(pkHex)
	fmt.Println("Verification for pk from hex -> ", ecdsa.Verify([]byte(message), pkFromHex, sig))
}
