package main

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"strings"
)

type KeyPair struct {
	PublicKey  PublicKey
	PrivateKey PrivateKey
}

type PublicKey struct {
	E       *big.Int
	Modulus *big.Int
}

type PrivateKey struct {
	D       *big.Int
	Modulus *big.Int
}

func main() {
	fmt.Printf("Let's create an RSA key pair\n")
	var filename string

	fmt.Print("Enter key name (no spaces allowed): ")
	_, err := fmt.Scan(&filename)
	if err != nil {
		fmt.Println("Error reading input:", err)
		os.Exit(1)
	}

	// Validate the input for spaces
	if strings.Contains(filename, " ") {
		panic("Input contains spaces! Please enter a valid input without spaces.")
	}

	pair := createNewKeyPair()
	writeKeyToFile(filename, pair)
}

func createNewKeyPair() KeyPair {
	BITS := 512
	var p, q, N *big.Int
	var errP, errQ error

	e := big.NewInt(65537)

	for {
		p, errP = rand.Prime(rand.Reader, BITS)
		if errP != nil {
			panic("Something went wrong with generating prime numbers")
		}

		// ensure that p and q are different, especially for small bit ranges
		for {
			q, errQ = rand.Prime(rand.Reader, BITS)
			if errQ != nil {
				panic("Something went wrong with generating prime numbers")
			}

			if q.Cmp(p) != 0 {
				break
			}
		}
		gcdPandE := new(big.Int).GCD(nil, nil, p, e)
		gcdQandE := new(big.Int).GCD(nil, nil, q, e)
		if gcdPandE.Cmp(big.NewInt(1)) == 0 && gcdQandE.Cmp(big.NewInt(1)) == 0 {
			break
		}
	}

	N = new(big.Int).Mul(p, q)
	phiP := new(big.Int).Sub(p, big.NewInt(1))
	phiQ := new(big.Int).Sub(q, big.NewInt(1))
	phi := new(big.Int).Mul(phiP, phiQ)
	d := new(big.Int).ModInverse(e, phi)

	fmt.Printf("Your p=%d, q=%d\n", p, q)
	fmt.Printf("Your N is: %d\n", N)
	fmt.Printf("Your Phi(N) is: %d\n", phi)
	fmt.Printf("Your e is: %d\n", e)
	fmt.Printf("Your d is: %d\n", d)

	return KeyPair{
		PublicKey: PublicKey{
			E:       e,
			Modulus: N,
		},
		PrivateKey: PrivateKey{
			D:       d,
			Modulus: N,
		},
	}
}

func writeKeyToFile(filename string, keys KeyPair) {
	// Marshal the struct into JSON
	publicData, publicErr := json.MarshalIndent(keys.PublicKey, "", "  ")
	privateData, privateErr := json.MarshalIndent(keys.PrivateKey, "", "  ")
	if publicErr != nil || privateErr != nil {
		panic("Could not write to serialize")
	}
	publicErr = os.WriteFile(filename+".pub", publicData, 0644)
	privateErr = os.WriteFile(filename, privateData, 0644)
	if publicErr != nil || privateErr != nil {
		panic("Could not write to file")
	}
}
