package main

import (
	"crypto/sha256"
	"fmt"
	"math/rand"
	"strconv"
)

// Constants for SHA-256
const (
	BLOCK_SIZE    = 64
	OUTPUT_SIZE   = 32
	INIT_HASH_LEN = 8
)

// SHA256 calculates the SHA-256 hash of the given data.
func SHA256(data []byte) [OUTPUT_SIZE]byte {
	// 	Initialize hash values:
	// (first 32 bits of the fractional parts of the square roots of the first 8 primes 2..19):
	hashValues := [INIT_HASH_LEN]uint32{
		0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
		0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
	}

	// Constants for the compression function (round constants)
	// (first 32 bits of the fractional parts of the cube roots of the first 64 primes 2..311):
	var k = [64]uint32{
		0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
		0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
		0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
		0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
		0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
		0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
		0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
		0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
		0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
		0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
		0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
		0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
		0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
		0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
		0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
		0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
	}

	// Pre-processing (Padding):
	paddedData := padData(data)

	// Process message in 512-bit blocks
	numBlocks := len(paddedData) / BLOCK_SIZE
	for i := 0; i < numBlocks; i++ {
		block := paddedData[i*BLOCK_SIZE : (i+1)*BLOCK_SIZE]
		w := make([]uint32, 64)

		// Prepare message schedule
		for t := 0; t < 16; t++ {
			w[t] = uint32(block[t*4])<<24 | uint32(block[t*4+1])<<16 |
				uint32(block[t*4+2])<<8 | uint32(block[t*4+3])
		}
		for t := 16; t < 64; t++ {
			s0 := rotr(w[t-15], 7) ^ rotr(w[t-15], 18) ^ (w[t-15] >> 3)
			s1 := rotr(w[t-2], 17) ^ rotr(w[t-2], 19) ^ (w[t-2] >> 10)
			w[t] = w[t-16] + s0 + w[t-7] + s1
		}

		// Initialize working variables to current hash value:
		a, b, c, d, e, f, g, h := hashValues[0], hashValues[1], hashValues[2], hashValues[3], hashValues[4], hashValues[5], hashValues[6], hashValues[7]

		// Compression function main loop:
		for t := 0; t < 64; t++ {
			s1 := rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25)
			ch := (e & f) ^ ((^e) & g)
			temp1 := h + s1 + ch + k[t] + w[t]
			s0 := rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22)
			maj := (a & b) ^ (a & c) ^ (b & c)
			temp2 := s0 + maj

			h, g, f, e, d, c, b, a = g, f, e, d+temp1, c, b, a, temp1+temp2
		}

		// Add the compressed chunk to the current hash value:
		hashValues[0] += a
		hashValues[1] += b
		hashValues[2] += c
		hashValues[3] += d
		hashValues[4] += e
		hashValues[5] += f
		hashValues[6] += g
		hashValues[7] += h
	}

	// Produce the final hash value (big-endian)
	var hash [32]byte
	for i := 0; i < INIT_HASH_LEN; i++ {
		hash[i*4] = byte(hashValues[i] >> 24)
		hash[i*4+1] = byte(hashValues[i] >> 16)
		hash[i*4+2] = byte(hashValues[i] >> 8)
		hash[i*4+3] = byte(hashValues[i])
	}

	return hash
}

// Pad the data according to SHA-256 padding rules.
func padData(data []byte) []byte {
	dataLen := len(data)
	padLen := BLOCK_SIZE - ((dataLen + 8) % BLOCK_SIZE)
	if padLen == 0 {
		padLen = BLOCK_SIZE
	}

	paddedData := make([]byte, dataLen+padLen+8)
	copy(paddedData, data)

	// Add a single '1' bit
	paddedData[dataLen] = 0x80

	// Add padding zeros
	for i := dataLen + 1; i < dataLen+padLen; i++ {
		paddedData[i] = 0x00
	}

	// Add message length in bits as big-endian
	bitLen := uint64(dataLen) * 8
	for i := 0; i < 8; i++ {
		paddedData[dataLen+padLen+i] = byte(bitLen >> ((7 - i) * 8))
	}

	return paddedData
}

// Rotate right (circular right shift) operation.
func rotr(x uint32, n uint) uint32 {
	return (x >> n) | (x << (32 - n))
}

// Test the SHA256 function
func main() {
	exampleMessage := `Lorem ipsum dolor sit amet, consectetur adipiscing elit. Aliquam ac sem et arcu molestie pretium ac non sapien.
	Vivamus vulputate eleifend feugiat. Cras mollis tincidunt nibh, et facilisis augue luctus ac. Curabitur convallis mattis dignissim.
	Pellentesque hendrerit tellus ex, sit amet accumsan libero sodales sed. Ut eget sodales massa, pretium convallis nisi.
	Etiam neque libero, sollicitudin quis tortor a, varius mollis sapien. Mauris a ligula imperdiet, placerat metus a, feugiat lacus.
	Ut tincidunt finibus sapien ut aliquam. Duis vestibulum erat nec leo tempor ultrices.
	Duis pretium, felis porta pharetra semper, ligula felis ullamcorper tortor, sit amet lacinia tortor nunc nec enim. Sed vitae porta velit.
	Sed vestibulum mollis est, sit amet vulputate tellus cursus et. Quisque id est vel ipsum pharetra dictum vitae in magna. Sed a elementum urna.
	Sed interdum a mauris vitae iaculis.`
	data := []byte(exampleMessage)
	fmt.Printf("Applying hash function on the following example message:\n%s\n", exampleMessage)
	hash := SHA256(data)
	cryptoHash := sha256.Sum256(data)

	fmt.Printf("The result of mine SHA256 hash function: %x\n", hash)
	fmt.Printf("The result of SHA256 hash function from crypto package: %x\n", cryptoHash)

	if hash != cryptoHash {
		fmt.Println("Mine SHA256 hash function doesn't work!")
		return
	}

	fmt.Printf("Hashes are the same!\n\n")

	fmt.Println("Algorithm validity test in progress...")
	for i := 0; i < 1000; i++ {
		str := []byte(strconv.FormatInt(int64(rand.Int()), 10))
		hash = SHA256(str)
		cryptoHash = sha256.Sum256(str)
		if hash != cryptoHash {
			fmt.Printf("Algorithm validity test ended with failure... SHA256 hash calculated by function from crypto package is different!\n")
			fmt.Printf("Mine SHA256 hash function result: %x\n, SHA256 hash function from crypto package result: %x\n", hash, cryptoHash)
			return
		}
	}
	fmt.Println("Algorithm validity test ended with success!")

	fmt.Println("Collision test in progress...")
	for i := 0; i < 1000; i++ {
		str1 := strconv.FormatInt(int64(rand.Int()), 10)
		str2 := strconv.FormatInt(int64(rand.Int()), 10)
		if str1 == str2 {
			continue
		}
		hash1 := SHA256([]byte(str1))
		hash2 := SHA256([]byte(str2))

		if hash1 == hash2 {
			fmt.Println("Collision test ended with failure... Hashes calculated from different input are the same!")
			fmt.Printf("Input 1: %s, Input 2: %s\n", str1, str2)
			fmt.Printf("hash 1: %x, hash2 2: %x\n", hash1, hash2)
			return
		}
	}
	fmt.Println("Collision validity test ended with success!")

}
