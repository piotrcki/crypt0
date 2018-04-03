//   Copyright (C) 2015 Piotr Chmielnicki
//
//   This program is free software; you can redistribute it and/or modify
//   it under the terms of the GNU General Public License as published by
//   the Free Software Foundation; either version 3 of the License, or
//   (at your option) any later version.
//
//   This program is distributed in the hope that it will be useful,
//   but WITHOUT ANY WARRANTY; without even the implied warranty of
//   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//   GNU General Public License for more details.
//
//   You should have received a copy of the GNU General Public License
//   along with this program; if not, write to the Free Software Foundation,
//   Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301  USA

package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha512"
	"fmt"
	"hash"
	"io"
	"os"
	"strings"
)

const ExitSuccess int = 0
const ExitPadTooShort int = 1
const ExitError int = 9
const PadExt string = ".w.pad"
const UsedPadExt string = ".x.pad"
const CiphertextExt string = ".enc"
const PadOverhead int64 = 144 // len(hmacKey) + len(AESKey) + len(head) = 96 + 32 + 16
const BufferSize int64 = 1024 * 1024

var Fplaintext *os.File = nil
var Fciphertext *os.File = nil
var Fpad *os.File = nil
var PlaintextSize int64 = -1
var PadSize int64 = -1
var PlaintextName string = ""
var CiphertextName string = ""
var PadName string = ""
var Short bool = false

var Hmac hash.Hash       // HMAC_SHA512
var Cipher cipher.Stream // AES256_CFB

func Usage() {
	fmt.Fprintf(os.Stderr, "Usage:\n\n")
	fmt.Fprintf(os.Stderr, "encrypt0 [--short] plaintext-file pad\n\n")
	fmt.Fprintf(os.Stderr, "plaintext-file: the file to encrypt\n")
	fmt.Fprintf(os.Stderr, "pad           : the pad to use (a .w.pad file)\n")
	fmt.Fprintf(os.Stderr, "--short       : do not add padding to the plaintext, the ciphertext will be shorter but will leak the file size\n\n")
	fmt.Fprintf(os.Stderr, "Return values:\n\n")
	fmt.Fprintf(os.Stderr, "0: encryption success\n")
	fmt.Fprintf(os.Stderr, "1: pad is too short\n")
	fmt.Fprintf(os.Stderr, "9: other error\n\n")
	CleanExit(ExitError)
}

func FatalCheck(err error) {
	if err != nil {
		FatalError(err.Error())
	}
}

func FatalError(err string) {
	fmt.Fprintf(os.Stderr, "encrypt0: error: %s\n", err)
	CleanExit(ExitError)
}

func CleanExit(status int) {
	if Fplaintext != nil {
		Fplaintext.Close()
	}
	if Fciphertext != nil {
		Fciphertext.Close()
		if status != ExitSuccess {
			os.Remove(CiphertextName)
		}
	}
	if Fpad != nil {
		Fpad.Close()
		// No rollback on the pad name here
	}
	os.Exit(status)
}

func ParseArgs() {
	length := len(os.Args)
	start := 1
	if (length == 4) && (os.Args[1] == "--short") {
		start = 2
		Short = true
	}
	if length != (start + 2) {
		Usage()
	}
	PlaintextName = os.Args[start]
	PadName = os.Args[start+1]
	indx := strings.Index(PadName, PadExt)
	if (indx <= 0) || (indx != (len(PadName) - len(PadExt))) {
		Usage()
	}
}

func CheckFiles() {
	inputInfo, err := os.Stat(PlaintextName)
	FatalCheck(err)
	padInfo, err := os.Stat(PadName)
	FatalCheck(err)
	if inputInfo.Mode().IsRegular() == false {
		FatalError(fmt.Sprintf("%s is not a regular file.", PlaintextName))
	}
	if padInfo.Mode().IsRegular() == false {
		FatalError(fmt.Sprintf("%s is not a regular file.", PadName))
	}
	if (padInfo.Size() - inputInfo.Size()) < PadOverhead {
		fmt.Fprintf(os.Stderr, "encrypt0: error: the pad is too short.\n")
		os.Exit(ExitPadTooShort)
	}
	PlaintextSize = inputInfo.Size()
	PadSize = padInfo.Size()
}

func GetHeader() []byte {
	ret := make([]byte, 16)
	var div int64 = 1
	for i := 0; i < 8; i++ {
		ret[i] = 0
	}
	for i := 15; i > 7; i-- {
		ret[i] = byte((PlaintextSize / div) % 256)
		div *= 256
	}
	return ret
}

func Init() {
	// Opening files
	var err error
	Fplaintext, err = os.Open(PlaintextName)
	FatalCheck(err)
	CiphertextName = fmt.Sprintf("%s%s", PlaintextName, CiphertextExt)
	Fciphertext, err = os.Create(CiphertextName)
	newPadName := strings.Replace(PadName, PadExt, UsedPadExt, -1)
	err = os.Rename(PadName, newPadName)
	FatalCheck(err)
	PadName = newPadName
	Fpad, err = os.Open(PadName)
	FatalCheck(err)
	// Setting up HMAC
	hmacKey := make([]byte, 96)
	_, err = io.ReadFull(Fpad, hmacKey)
	FatalCheck(err)
	Hmac = hmac.New(sha512.New, hmacKey)
	// Setting up AES
	iv := make([]byte, 16)
	_, err = rand.Read(iv) // There is a ReadFull inside rand.Read
	FatalCheck(err)
	_, err = Fciphertext.Write(iv)
	FatalCheck(err)
	Hmac.Write(iv)
	aesKey := make([]byte, 32)
	_, err = io.ReadFull(Fpad, aesKey)
	FatalCheck(err)
	AES, err := aes.NewCipher(aesKey)
	FatalCheck(err)
	Cipher = cipher.NewCFBEncrypter(AES, iv)
}

func Encrypt() {
	// Getting and encrypt the header
	head := GetHeader()
	headPad := make([]byte, 16)
	_, err := io.ReadFull(Fpad, headPad)
	FatalCheck(err)
	for i := 0; i < 16; i++ {
		head[i] ^= headPad[i]
	}
	Cipher.XORKeyStream(head, head)
	_, err = Fciphertext.Write(head)
	FatalCheck(err)
	Hmac.Write(head)
	// Encrypting the plaintext
	// Blocks are to avoid buffering all the file
	var blocks int64 = (PlaintextSize / BufferSize) + 1
	var i, j int64
	for i = 0; i < blocks; i++ {
		todo := BufferSize
		if i == (blocks - 1) {
			todo = PlaintextSize % BufferSize
		}
		if todo == 0 {
			continue
		}
		buff := make([]byte, todo)
		padBuff := make([]byte, todo)
		_, err = io.ReadFull(Fplaintext, buff)
		FatalCheck(err)
		_, err = io.ReadFull(Fpad, padBuff)
		FatalCheck(err)
		for j = 0; j < todo; j++ {
			buff[j] ^= padBuff[j]
		}
		Cipher.XORKeyStream(buff, buff)
		_, err = Fciphertext.Write(buff)
		Hmac.Write(buff)
	}
	// Adding and encrypting 0x00 padding
	if !Short {
		var toWrite int64 = PadSize - PadOverhead - PlaintextSize
		blocks = (toWrite / BufferSize) + 1
		for i = 0; i < blocks; i++ {
			todo := BufferSize
			if i == (blocks - 1) {
				todo = toWrite % BufferSize
			}
			padBuff := make([]byte, todo)
			_, err = io.ReadFull(Fpad, padBuff)
			FatalCheck(err)
			// No xor loop here because padding value is 0x00
			Cipher.XORKeyStream(padBuff, padBuff)
			_, err = Fciphertext.Write(padBuff)
			FatalCheck(err)
			Hmac.Write(padBuff)
		}
	}
	// Writing the HMAC at the end of the ciphertext
	_, err = Fciphertext.Write(Hmac.Sum(nil))
	FatalCheck(err)
}

func main() {
	ParseArgs()
	CheckFiles()
	Init()
	Encrypt()
	fmt.Printf("encrypt0: success: `%s` successfully encrypted using `%s`.\n",
		PlaintextName, PadName)
	CleanExit(ExitSuccess)
}
