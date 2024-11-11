package main

import (
	"bufio"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"flag"
	"fmt"
	"log"
	"os"
	"sync"
	"time"
)

const (
	Red    = "\033[31m"
	Green  = "\033[32m"
	Yellow = "\033[33m"
	Blue   = "\x1b[38;5;111m"
	Reset  = "\033[0m"
	HideCursor = "\033[?25l"
	ShowCursor = "\033[?25h"
)

func asciiart() {
	var art string
	art += "                 _     _       \n"
    art += "  /\\  /\\__ _ ___| |__ (_)_ __  \n"
    art += " / /_/ / _` / __| '_ \\| | '_ \\ \n"
    art += "/ __  / (_| \\__ \\ | | | | | | | @MachIaVellill\n"
    art += "\\/ /_/ \\__,_|___/_| |_|_|_| |_|\n\n"
	fmt.Printf("%s%s%s", Blue,art, Reset)
}

func main() {
	asciiart()
	var (
		WordList = flag.String("w", "", "The wordlist path to use. [Required]\n Example: /path/to/wordlist")
		HashType = flag.String("x", "", "Hash algorithm (MD5, SHA256, SHA512, SHA1) [Required]")
		Hash     = flag.String("s", "", "The hash you want to crack [Required]")
	)

	flag.Parse()

	if *WordList == "" || *HashType == "" || *Hash == "" || os.Args[1] == "" {
		flag.Usage()
		os.Exit(1)
	}

	W, err := os.Open(*WordList)
	if err != nil {
		log.Fatalln(err)
	}
	defer W.Close()

	var (
		passwordAttempts = make(chan string)
		found            = make(chan string)
		wg               sync.WaitGroup
	)

	// hide the cursor at the start (The confusing |)
	fmt.Print(HideCursor)
	defer fmt.Print(ShowCursor) // ensure the cursor is shown again at the end

	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case attempt := <-passwordAttempts:
				// some padding for clearer display
				fmt.Printf("\r%s[*] Trying password: %-100s%s", Yellow, attempt, Reset)
			case cracked := <-found:
				fmt.Printf("\r%s[*] Hash Cracked: %-100s%s\n", Green, cracked, Reset)
				return
			}
		}
	}()

	// Detect if the hash cracked
	hashCracked := false

	scanner := bufio.NewScanner(W)
	for scanner.Scan() {
		password := scanner.Text()
		passwordAttempts <- password

		var hash string
		switch *HashType {
		case "MD5":
			hash = fmt.Sprintf("%x", md5.Sum([]byte(password)))
			// Crack this > 5f6e11a0d425695547d599b39e84d50b
		case "SHA1":
			hash = fmt.Sprintf("%x", sha1.Sum([]byte(password)))
		case "SHA256":
			hash = fmt.Sprintf("%x", sha256.Sum256([]byte(password)))
		case "SHA512":
			hash = fmt.Sprintf("%x", sha512.Sum512([]byte(password)))
		default:
			log.Fatalln("Unsupported hash type provided.")
		}

		if hash == *Hash {
			found <- password
			hashCracked = true
			close(passwordAttempts)
			break
		}
		time.Sleep(50 * time.Millisecond) // Optional: slows down for a clearer display
	}

	close(found)
	wg.Wait()

	if !hashCracked {
		fmt.Printf("\r%s[*] Password not found in the wordlist, try another wordlist%s\n", Red, Reset)
	}

	if err := scanner.Err(); err != nil {
		log.Fatalln(err)
	}
}
