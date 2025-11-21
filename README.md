# fletcher4

A Go library for computing Fletcher-4 checksums (as used in ZFS), implementing the `hash.Hash` interface. This algorithm produces a 256-bit checksum (4 x 64-bit words).

## Installation

```bash
go get go.solidsystem.no/fletcher4
```

## Usage

```go
package main

import (
	"fmt"
	"go.solidsystem.no/fletcher4"
)

func main() {
	f := fletcher4.New()
	f.Write([]byte("hello world"))

	// Get the 4 uint64 checksum words
	sum := f.Sum64x4()
	fmt.Printf("Checksum: %v\n", sum)
}
```
