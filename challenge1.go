// crypto challenge 1 - https://cryptopals.com/sets/1
package main

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
)


func HexToBase64(s string)(string, error) {
	decodedString, err := hex.DecodeString(s)
	if err != nil {
		return "", err
	}
	base64String := base64.RawStdEncoding.EncodeToString(decodedString)
	return base64String, nil
	
	
}



// Exercise 1 - convert hex to base64
// expect: 49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d
// return: SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t
func Test1() {
	input := "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
	expected := "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"

	result, _ := HexToBase64(input)
	fmt.Printf("result: %s, expected: %s\n", result, expected)
}

// Exercise 2 - Fixed XOR
func Test2() {
	input, err := hex.DecodeString("1c0111001f010100061a024b53535009181c")
	input2, err := hex.DecodeString("686974207468652062756c6c277320657965")
	expected := "746865206b696420646f6e277420706c6179"
	if err != nil {
		fmt.Println("Error")
	}

	var result = make([]byte, len(input))
	for i := 0; i < len(input); i++ {
		result[i] = input[i] ^ input2[i]
	}
	
	fmt.Printf("result: %s, expected: %s\n", hex.EncodeToString(result), expected)
}

// Exercise 3 - Single-byte XOR cipher
func Test3() {
	input, _ := hex.DecodeString("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")
	var sol []byte
	current_score := 0
	for i := 0; i <= 256; i++ {
		x := byte(i)
		temp := make([]byte, len(input))
		var score = 0
		for j := 0; j < len(input); j++ {
			temp[j] = input[j] ^ x
			s := rune(temp[j])
			if (s >= 'A' && s <= 'Z') || (s >= 'a' && s <= 'z') {
				score++
			}
		}

		fmt.Printf("%i\n", score)
		if score > current_score {
			current_score = score
			sol = temp
		}
	}
	// String sol prints: Cooking MC's like a pound of bacon
	fmt.Printf("Result Test3: %s\n", string(sol))


}
