package main

import (
	"bufio"
	"crypto/rand"
	"encoding/json"
	"flag"
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
	var fFlag = flag.String("f", "", "-f path to key file")
	flag.Parse()
	if flag.Arg(0) == "generate" {
		generateKey()
	} else if flag.Arg(0) == "encrypt" {
		if *fFlag == "" {
			fmt.Println("Invalid flags, see --help")
		}
		encryptText(*fFlag)
	} else if flag.Arg(0) == "decrypt" {
		if *fFlag == "" {
			fmt.Println("Invalid flags, see --help")
		}
		decryptText(*fFlag)
	} else {
		fmt.Println("Invalid flags, see --help")
	}
}

func addPKCSPadding(messageBytes []byte, blockSize int) []byte {
	messageLength := len(messageBytes)
	if messageLength > blockSize-11 {
		panic("Message is too long for RSA encryption")
	}
	paddingLength := blockSize - messageLength - 3
	padding := make([]byte, paddingLength)
	_, err := rand.Read(padding)
	if err != nil {
		panic("Something went wrong with the padding generation")
	}

	for i := range padding {
		for padding[i] == 0 {
			randValue, err := rand.Int(rand.Reader, big.NewInt(255))
			if err != nil {
				panic("Something went wrong with the random number generation")
			}
			value := byte(randValue.Uint64())
			if value != 0 {
				padding[i] = value
			}
		}
	}

	header := []byte{0x00, 0x02}
	PS := append(padding, 0x00)

	paddedMessage := append(header, append(PS, messageBytes...)...)

	return paddedMessage
}

func removePKCSPadding(cipherBytes []byte) []byte {
	if cipherBytes[0] != 0x02 {
		panic("Incorrect formatting of encrypted string")
	}

	i := 2
	cipherLength := len(cipherBytes)
	for i < cipherLength {
		if cipherBytes[i] == 0x00 {
			i++
			break
		}
		i++
	}

	if i == cipherLength {
		panic("No message string")
	}

	return cipherBytes[i:]
}

func encryptText(filepath string) {
	key := readKeyFromFile(filepath).PublicKey
	reader := bufio.NewReader(os.Stdin)

	fmt.Print("Enter the message to encrypt: ")
	// Read the input line
	messageText, err := reader.ReadString('\n')
	if err != nil {
		fmt.Println("Error reading input:", err)
		os.Exit(1)
	}

	// Remove the newline character
	messageText = messageText[:len(messageText)-1] // Remove t

	// Get the modulus size in bytes
	modulusBytes := (key.Modulus.BitLen() + 7) / 8

	messageBytes := []byte(messageText)
	paddedMessage := addPKCSPadding(messageBytes, modulusBytes)

	message := new(big.Int).SetBytes(paddedMessage)

	cipher := new(big.Int).Exp(message, key.E, key.Modulus)
	fmt.Printf("Your Cipher Text:\n\n%d\n\n", cipher)
}

func decryptText(filepath string) {
	key := readKeyFromFile(filepath).PrivateKey
	reader := bufio.NewReader(os.Stdin)

	fmt.Print("Enter the cipher text to decrypt: ")
	cipherText, err := reader.ReadString('\n')
	if err != nil {
		fmt.Println("Error reading input:", err)
		os.Exit(1)
	}

	cipherText = cipherText[:len(cipherText)-1] // Remove trailing newline
	cipher, success := new(big.Int).SetString(cipherText, 10)
	if !success {
		panic("Failed to convert the cipher text to a big integer")
	}

	// Decrypt using RSA
	message := new(big.Int).Exp(cipher, key.D, key.Modulus)
	messageBytes := message.Bytes()

	// Remove the padding
	removePadding := removePKCSPadding(messageBytes)
	fmt.Printf("\n\nYour Message Text:\n\n%s\n\n", string(removePadding))
}

func generateKey() {
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
	writeKeyToFile("keys/"+filename, pair)
}

func createNewKeyPair() KeyPair {
	BITS := 2048
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

func readKeyFromFile(filename string) KeyPair {
	data, err := os.ReadFile(filename)
	if err != nil {
		panic("Error reading " + filename)
	}

	if strings.Contains(filename, ".pub") {
		var k PublicKey
		err = json.Unmarshal(data, &k)
		return KeyPair{
			PublicKey:  k,
			PrivateKey: PrivateKey{},
		}
	} else {
		var k PrivateKey
		err = json.Unmarshal(data, &k)
		return KeyPair{
			PrivateKey: k,
			PublicKey:  PublicKey{},
		}
	}
}
