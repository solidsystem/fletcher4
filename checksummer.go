// Copyright: Jostein Stuhaug
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package fletcher4 // import go.solidsystem.no/fletcher4

import (
	"encoding/binary"
	"fmt"
	"hash"
)

// Extension of common Hash interface to easily get 4 computed checksum words
type Fletcher64x4 interface {
	hash.Hash
	Sum64x4() [4]uint64
}

// The size of a fletcher4 checksum in bytes
const Size = 32

// Must be the same as size of uint32 with the current implementation. Not entirely sure it's the correct value to return as blocksize, but think so.
const BlockSize = 4

// digest represents the partial evaluation of a fletcher4 checksum.
type digest struct {
	sum  [4]uint64
	buf  [BlockSize]byte
	nbuf int
}

func (d *digest) Reset() {
	d.sum = [4]uint64{0, 0, 0, 0}
	d.buf = [BlockSize]byte{}
	d.nbuf = 0
}

// New returns a new Fletcher64x4 (hash.Hash) computing the fletcher4 checksum.
func New() Fletcher64x4 {
	d := new(digest)
	d.Reset()
	return d
}

func (d *digest) Size() int { return Size }

func (d *digest) BlockSize() int {
	return BlockSize
}

func (d *digest) update(p []byte) {
	if len(p)%BlockSize != 0 {
		panic(fmt.Sprintf("update to Fletcher64x4 checksummer digest must be a multiple of %v bytes.", BlockSize))
	}
	for i := 0; i < len(p); i += BlockSize {
		d.sum[0] += uint64(binary.LittleEndian.Uint32(p[i : i+BlockSize]))
		d.sum[1] += d.sum[0]
		d.sum[2] += d.sum[1]
		d.sum[3] += d.sum[2]
	}
}

func (d *digest) Write(p []byte) (n int, err error) {
	n = len(p)
	if d.nbuf > 0 {
		copied := copy(d.buf[d.nbuf:], p)
		d.nbuf += copied
		p = p[copied:]
		if d.nbuf == BlockSize {
			d.update(d.buf[:])
			d.nbuf = 0
		}
	}
	if len(p) >= BlockSize {
		alignedLen := len(p) &^ (BlockSize - 1)
		d.update(p[:alignedLen])
		p = p[alignedLen:]
	}
	if len(p) > 0 {
		d.nbuf = copy(d.buf[:], p)
	}
	return n, nil
}

func (d *digest) Sum(in []byte) []byte {
	s := d.Sum64x4()
	add := make([]byte, 8)
	binary.LittleEndian.PutUint64(add, s[0])
	ret := append(in, add...)
	binary.LittleEndian.PutUint64(add, s[1])
	ret = append(ret, add...)
	binary.LittleEndian.PutUint64(add, s[2])
	ret = append(ret, add...)
	binary.LittleEndian.PutUint64(add, s[3])
	ret = append(ret, add...)

	return ret
}

// Returns the current checksum
func (d *digest) Sum64x4() [4]uint64 {
	sum := d.sum
	if d.nbuf > 0 {
		var buf [BlockSize]byte
		copy(buf[:], d.buf[:d.nbuf])
		// Pad with zeros (implicit since buf is zero-initialized)
		val := uint64(binary.LittleEndian.Uint32(buf[:]))
		sum[0] += val
		sum[1] += sum[0]
		sum[2] += sum[1]
		sum[3] += sum[2]
	}
	return sum
}
