// xorgen generates XOR+base64 obfuscated literals for internal/obfs.
//
// Usage:
//
//	deadbyte-xorgen -key 167 "https://c2.example/panel"
//	echo "secret" | deadbyte-xorgen
package main

import (
	"bufio"
	"encoding/base64"
	"flag"
	"fmt"
	"os"
)

func main() {
	key := flag.Int("key", 0xA7, "XOR key byte (0-255)")
	flag.Parse()
	enc := func(s string) string {
		b := []byte(s)
		for i := range b {
			b[i] ^= byte(*key)
		}
		return base64.StdEncoding.EncodeToString(b)
	}
	if flag.NArg() > 0 {
		for _, a := range flag.Args() {
			fmt.Printf("obfs.S(%q, %d) // %q\n", enc(a), *key, a)
		}
		return
	}
	sc := bufio.NewScanner(os.Stdin)
	for sc.Scan() {
		line := sc.Text()
		if line == "" {
			continue
		}
		fmt.Printf("obfs.S(%q, %d) // %q\n", enc(line), *key, line)
	}
}
