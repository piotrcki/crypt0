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
	"crypto/rand"
	"encoding/csv"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"
)

const ExitSuccess int = 0
const ExitError int = 9
const DirExt string = ".pads"

var Todo [][]string
var Number uint64
var Size uint64
var Cipher cipher.Stream // AES256_CTR
var Sources []*os.File

func Usage() {
	fmt.Fprintf(os.Stderr, "Usage:\n\n")
	fmt.Fprintf(os.Stderr, "form 1: genpads0 size pad-name\n")
	fmt.Fprintf(os.Stderr, "form 2: genpads0 size number peer1 peer2\n")
	fmt.Fprintf(os.Stderr, "form 3: genpads0 size number peers-file\n\n")
	fmt.Fprintf(os.Stderr, "size      : size of a pad in kio (1 kio = 1024 bytes)\n")
	fmt.Fprintf(os.Stderr, "pad-name  : file name of the pad to generate\n")
	fmt.Fprintf(os.Stderr, "number    : number of pads to generate per communication way\n")
	fmt.Fprintf(os.Stderr, "peer1|2   : peer's name (Such as \"Alice\" or \"Bob\"\n")
	fmt.Fprintf(os.Stderr, "peers-file: a CSV file containing communication channel between peers\n")
	fmt.Fprintf(os.Stderr, "            each line is on the following form SENDER,RECIPIENT1[,RECIPIENT2[...]]\n\n")
	fmt.Fprintf(os.Stderr, "Environment:\n\n")
	fmt.Fprintf(os.Stderr, "CSTRNG: cryptographically secure true random number generator. Readable file expected (multiple files can be supplied separated by ':')\n")
	fmt.Fprintf(os.Stderr, "PRNG  : pseudo-random number generator. Readable file expected (multiple files can be supplied separated by ':')\n\n")
	fmt.Fprintf(os.Stderr, "Return values:\n\n")
	fmt.Fprintf(os.Stderr, "0: success\n")
	fmt.Fprintf(os.Stderr, "9: error\n")
	os.Exit(ExitError)
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
	for _, f := range Sources {
		if f != nil {
			f.Close()
		}
	}
	os.Exit(status)
}

func InitRandom() {
	var sources []string
	sources = append(sources, strings.Split(os.Getenv("CSTRNG"), ":")...)
	if len(sources) == 0 || ((len(sources) == 1) && (sources[0] == "")) {
		fmt.Printf("genpads0: warning: no CSTRNG in use (this should remain secure in most cases).\n")
	}
	sources = append(sources, strings.Split(os.Getenv("PRNG"), ":")...)
	for _, source := range sources {
		if source != "" {
			f, err := os.Open(source)
			FatalCheck(err)
			Sources = append(Sources, f)
		}
	}
	iv := make([]byte, 16)
	aesKey := make([]byte, 32)
	_, err := rand.Read(iv) // There is a ReadFull inside rand.Read
	FatalCheck(err)
	_, err = rand.Read(aesKey)
	FatalCheck(err)
	for _, f := range Sources {
		var i uint64
		_iv := make([]byte, 16)
		_aesKey := make([]byte, 32)
		_, err = io.ReadFull(f, iv)
		FatalCheck(err)
		_, err = io.ReadFull(f, aesKey)
		FatalCheck(err)
		for i = 0; i < 16; i++ {
			iv[i] ^= _iv[i]
		}
		for i = 0; i < 32; i++ {
			aesKey[i] ^= _aesKey[i]
		}
	}
	AES, err := aes.NewCipher(aesKey)
	FatalCheck(err)
	Cipher = cipher.NewCTR(AES, iv)
}

func GeneratePad(padName, padCopy string) {
	var file1 *os.File = nil
	var file2 *os.File = nil
	file1, err := os.Create(padName)
	FatalCheck(err)
	defer file1.Close()
	if padCopy != "" {
		file2, err = os.Create(padCopy)
		FatalCheck(err)
		defer file2.Close()
	}
	buffer := make([]byte, 1024)
	var i, j uint64
	for i = 0; i < Size; i++ {
		_, err = rand.Read(buffer)
		FatalCheck(err)
		for _, f := range Sources {
			_buffer := make([]byte, 1024)
			_, err := io.ReadFull(f, _buffer)
			FatalCheck(err)
			for j = 0; j < 1024; j++ {
				buffer[j] ^= _buffer[j]
			}
		}
		Cipher.XORKeyStream(buffer, buffer)
		_, err = file1.Write(buffer)
		FatalCheck(err)
		if file2 != nil {
			_, err = file2.Write(buffer)
			FatalCheck(err)
		}
	}
}

func DoTheWork() {
	var i, j int
	var k uint64
	for i = 0; i < len(Todo); i++ {
		for j = 1; j < len(Todo[i]); j++ {
			for k = 0; k < Number; k++ {
				wDir := fmt.Sprintf("%s%s%c%s", Todo[i][0], DirExt,
					os.PathSeparator, Todo[i][j])
				rDir := fmt.Sprintf("%s%s%c%s", Todo[i][j], DirExt,
					os.PathSeparator, Todo[i][0])
				FatalCheck(os.MkdirAll(wDir, 0700))
				FatalCheck(os.MkdirAll(rDir, 0700))
				baseName := strconv.FormatInt(time.Now().UnixNano(), 16)
				GeneratePad(fmt.Sprintf("%s%c%s.w.pad", wDir, os.PathSeparator, baseName),
					fmt.Sprintf("%s%c%s.r.pad", rDir, os.PathSeparator, baseName))
			}
		}
	}
}

func main() {
	var err error
	if len(os.Args) == 3 {
		Size, err = strconv.ParseUint(os.Args[1], 10, 64)
		if err != nil {
			Usage()
		}
		InitRandom()
		GeneratePad(os.Args[2], "")
	} else if len(os.Args) == 5 {
		Size, err = strconv.ParseUint(os.Args[1], 10, 64)
		if err != nil {
			Usage()
		}
		Number, err = strconv.ParseUint(os.Args[2], 10, 64)
		if err != nil {
			Usage()
		}
		InitRandom()
		Todo = make([][]string, 2)
		Todo[0] = make([]string, 2)
		Todo[1] = make([]string, 2)
		Todo[0][0] = os.Args[3]
		Todo[1][1] = os.Args[3]
		Todo[0][1] = os.Args[4]
		Todo[1][0] = os.Args[4]
		DoTheWork()
	} else if len(os.Args) == 4 {
		Size, err = strconv.ParseUint(os.Args[1], 10, 64)
		if err != nil {
			Usage()
		}
		Number, err = strconv.ParseUint(os.Args[2], 10, 64)
		if err != nil {
			Usage()
		}
		InitRandom()
		file, err := os.Open(os.Args[3])
		FatalCheck(err)
		defer file.Close()
		csvReader := csv.NewReader(file)
		csvReader.FieldsPerRecord = -1
		Todo, err = csvReader.ReadAll()
		FatalCheck(err)
		DoTheWork()
	} else {
		Usage()
	}
	fmt.Printf("genpads0: success.\n")
	CleanExit(ExitSuccess)
}
