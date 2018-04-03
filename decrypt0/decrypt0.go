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
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha512"
	"fmt"
	"hash"
	"io"
	"io/ioutil"
	"os"
	"strings"
)

const ExitSuccess int = 0
const ExitNoValidPad int = 1
const ExitError = 9
const CiphertextExt string = ".enc"
const PadExt string = ".r.pad"
const PadOverhead int64 = 48        // 144 - 96
const CiphertextOverhead int64 = 96 // len(sha512) + len(head) + len(iv) = 64 + 16 + 16
const BufferSize int64 = 1024 * 1024

var Fplaintext *os.File = nil
var Fciphertext *os.File = nil
var Fpad *os.File = nil
var PlaintextSize int64 = -1
var CiphertextSize int64 = -1
var PadSize int64 = -1
var PlaintextName string = ""
var CiphertextName string = ""
var PadName string = ""

var Hmac hash.Hash       // HMAC_SHA512
var Cipher cipher.Stream // AES256_CFB

func Usage() {
	fmt.Fprintf(os.Stderr, "Usage:\n\n")
	fmt.Fprintf(os.Stderr, "decrypt0 ciphertext-file pad\n\n")
	fmt.Fprintf(os.Stderr, "ciphertext-file: the file to decrypt (a .enc file)\n")
	fmt.Fprintf(os.Stderr, "pad            : the pad (a .r.pad file) to use or a directory containing it\n\n")
	fmt.Fprintf(os.Stderr, "Return values:\n\n")
	fmt.Fprintf(os.Stderr, "0: decryption success\n")
	fmt.Fprintf(os.Stderr, "1: invalid pad or no valid pad in the directory\n")
	fmt.Fprintf(os.Stderr, "9: other error\n")
	CleanExit(ExitError)
}

func FatalCheck(err error) {
	if err != nil {
		FatalError(err.Error())
	}
}

func FatalError(err string) {
	fmt.Fprintf(os.Stderr, "decrypt0: error: %s\n", err)
	CleanExit(ExitError)
}

func CleanExit(status int) {
	if Fciphertext != nil {
		Fciphertext.Close()
	}
	if Fplaintext != nil {
		Fplaintext.Close()
		if status != ExitSuccess {
			os.Remove(PlaintextName)
		}
	}
	if Fpad != nil {
		Fpad.Close()
		// No rollback on the pad name here
	}
	os.Exit(status)
}

func ParseArgs() {
	if len(os.Args) != 3 {
		Usage()
	}
	CiphertextName = os.Args[1]
	PadName = os.Args[2]
	indx := strings.Index(CiphertextName, CiphertextExt)
	if (indx <= 0) || (indx != (len(CiphertextName) - len(CiphertextExt))) {
		Usage()
	}
}

func OpenFiles() {
	var err error
	if len(PadName) > 0 {
		Fpad, err = os.Open(PadName)
		FatalCheck(err)
	}
	if len(CiphertextName) > 0 {
		Fciphertext, err = os.Open(CiphertextName)
		FatalCheck(err)
	}
	if len(PlaintextName) > 0 {
		Fplaintext, err = os.Create(PlaintextName)
		FatalCheck(err)
	}
}

func CheckIntegrity() bool {
	OpenFiles()
	defer Fciphertext.Close()
	defer Fpad.Close()
	// Reading HMAC key, AES key and header from the pad
	hmacKey := make([]byte, 96)
	_, err := io.ReadFull(Fpad, hmacKey)
	FatalCheck(err)
	aesKey := make([]byte, 32)
	_, err = io.ReadFull(Fpad, aesKey)
	FatalCheck(err)
	headPad := make([]byte, 8)
	_, err = io.ReadFull(Fpad, headPad)
	FatalCheck(err)
	Hmac = hmac.New(sha512.New, hmacKey)
	AES, err := aes.NewCipher(aesKey)
	FatalCheck(err)
	// Reading IV and first encrypted 8 bytes from the ciphertext
	iv := make([]byte, 16)
	_, err = io.ReadFull(Fciphertext, iv)
	FatalCheck(err)
	head := make([]byte, 8)
	_, err = io.ReadFull(Fciphertext, head)
	FatalCheck(err)
	// Doing a fast test
	Hmac := hmac.New(sha512.New, hmacKey)
	Hmac.Write(iv)
	Hmac.Write(head)
	Cipher = cipher.NewCFBDecrypter(AES, iv)
	Cipher.XORKeyStream(head, head)
	if !bytes.Equal(head, headPad) {
		// If this fail, stop here
		return false
	}
	// Else, go ahead and check the rest of the ciphertext
	var toRead int64 = CiphertextSize - 64 - (8 + 16) // (8 + 16) => already read; 64 => len(hmac)
	var blocks int64 = (toRead / BufferSize) + 1
	var i int64
	for i = 0; i < blocks; i++ {
		todo := BufferSize
		if i == (blocks - 1) {
			todo = toRead % BufferSize
		}
		buff := make([]byte, todo)
		_, err = io.ReadFull(Fciphertext, buff)
		FatalCheck(err)
		Hmac.Write(buff)
	}
	hmac := make([]byte, 64)
	_, err = io.ReadFull(Fciphertext, hmac)
	if bytes.Equal(hmac, Hmac.Sum(nil)) {
		return true
	}
	return false
}

func FindPad() bool {
	if CiphertextSize == -1 {
		inputInfo, err := os.Stat(CiphertextName)
		FatalCheck(err)
		if inputInfo.Mode().IsRegular() == false {
			FatalError(fmt.Sprintf("%s is not a regular file.", CiphertextName))
		}
		CiphertextSize = inputInfo.Size()
	}
	info, err := os.Stat(PadName)
	FatalCheck(err)
	if info.Mode().IsRegular() && ((info.Size() - CiphertextSize) >= PadOverhead) {
		indx := strings.Index(PadName, PadExt)
		if (indx > 0) && (indx == (len(PadName) - len(PadExt))) {
			return CheckIntegrity()
		}
	} else if info.Mode().IsDir() {
		infos, err := ioutil.ReadDir(PadName)
		FatalCheck(err)
		oldPadName := PadName
		for _, f := range infos {
			PadName = fmt.Sprintf("%s%c%s", oldPadName, os.PathSeparator, f.Name())
			isOk := FindPad()
			if isOk {
				return true
			}
			PadName = oldPadName
		}
	}
	return false
}

func DecryptInit() {
	PlaintextName = strings.Replace(CiphertextName, ".enc", "", -1)
	OpenFiles()
	// Reading HMAC key, AES key and header from the pad
	hmacKey := make([]byte, 96)
	_, err := io.ReadFull(Fpad, hmacKey)
	FatalCheck(err)
	aesKey := make([]byte, 32)
	_, err = io.ReadFull(Fpad, aesKey)
	FatalCheck(err)
	headPad := make([]byte, 16)
	_, err = io.ReadFull(Fpad, headPad)
	FatalCheck(err)
	Hmac = hmac.New(sha512.New, hmacKey)
	AES, err := aes.NewCipher(aesKey)
	FatalCheck(err)
	// Reading IV and first encrypted 16 bytes from the ciphertext
	iv := make([]byte, 16)
	_, err = io.ReadFull(Fciphertext, iv)
	FatalCheck(err)
	head := make([]byte, 16)
	_, err = io.ReadFull(Fciphertext, head)
	FatalCheck(err)
	Cipher = cipher.NewCFBDecrypter(AES, iv)
	// Decrypting the header
	Cipher.XORKeyStream(head, head)
	for i := 0; i < 16; i++ {
		head[i] ^= headPad[i]
	}
	// Getting the plaintext size
	PlaintextSize = 0
	for i := 8; i < 16; i++ {
		PlaintextSize *= 256
		PlaintextSize += int64(head[i])
	}
	if (PlaintextSize < 0) || ((CiphertextSize - PlaintextSize) < CiphertextOverhead) {
		FatalError(fmt.Sprintf("%s is authenticated but malformed.", CiphertextName))
	}
}

func Decrypt() {
	// Decrypting the actual plaintext
	var blocks int64 = (PlaintextSize / BufferSize) + 1
	var i, j int64
	for i = 0; i < blocks; i++ {
		todo := BufferSize
		if todo == 0 {
			continue
		}
		if i == (blocks - 1) {
			todo = PlaintextSize % BufferSize
		}
		buff := make([]byte, todo)
		padBuff := make([]byte, todo)
		_, err := io.ReadFull(Fciphertext, buff)
		FatalCheck(err)
		_, err = io.ReadFull(Fpad, padBuff)
		FatalCheck(err)
		Cipher.XORKeyStream(buff, buff)
		for j = 0; j < todo; j++ {
			buff[j] ^= padBuff[j]
		}
		_, err = Fplaintext.Write(buff)
	}
}

func main() {
	ParseArgs()
	if !FindPad() {
		fmt.Fprintf(os.Stderr, "decrypt0: error: failed to find valid pad for `%s`.\n", CiphertextName)
		CleanExit(ExitNoValidPad)
	}
	DecryptInit()
	Decrypt()
	fmt.Printf("decrypt0: success: `%s` successfully authenticated and decrypted using `%s`.",
		CiphertextName, PadName)
	CleanExit(ExitSuccess)
}
