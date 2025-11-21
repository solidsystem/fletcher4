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

package fletcher4

import (
	"bytes"
	"fmt"
	"testing"
)

type hexRes [4]string

func compare(t *testing.T, leadTxt string, exp hexRes, got [4]uint64) {
	gotHex := fmt.Sprintf("%x/%x/%x/%x", got[0], got[1], got[2], got[3])
	expHex := fmt.Sprintf("%v/%v/%v/%v", exp[0], exp[1], exp[2], exp[3])

	if expHex != gotHex {
		t.Errorf("%v:\nexpected\t%v,\ngot\t\t%v", leadTxt, expHex, gotHex)
	}
}

// Test that writing 4 bytes fills all checksum result uints with the same 4 bytes
func TestChecksummer1(t *testing.T) {
	inp1 := []byte{1, 2, 3, 4}
	exp1 := hexRes{"4030201", "4030201", "4030201", "4030201"}

	checksummer := New()
	if _, err := checksummer.Write(inp1); err != nil {
		t.Fatal(err)
	}
	res1 := checksummer.Sum64x4()
	compare(t, "Checksum test 1, 4 bytes failed", exp1, res1)

}

// Test that writing 8 bytes and then 4 more gives correct result.
// Also test that Sum return correct result
func TestChecksummer2(t *testing.T) {
	inp1 := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	exp1 := hexRes{"c0a0806", "100d0a07", "14100c08", "18130e09"}

	checksummer := New()
	if _, err := checksummer.Write(inp1); err != nil {
		t.Fatal(err)
	}
	res1 := checksummer.Sum64x4()
	compare(t, "Checksum test 2, 8 bytes written failed", exp1, res1)

	inp2 := []byte{2, 4, 6, 8}
	exp2 := hexRes{"14100c08", "241d160f", "382d2217", "50403020"}
	if _, err := checksummer.Write(inp2); err != nil {
		t.Fatal(err)
	}
	res2 := checksummer.Sum64x4()
	compare(t, "Checksum test 2, 12 bytes written failed", exp2, res2)

	var sum []byte
	sum = checksummer.Sum(sum)
	expSum := []byte{8, 12, 16, 20, 0, 0, 0, 0, 15, 22, 29, 36, 0, 0, 0, 0, 23, 34, 45, 56, 0, 0, 0, 0, 32, 48, 64, 80, 0, 0, 0, 0}
	if !bytes.Equal(sum, expSum) {
		t.Errorf("Checksum Sum method call 1 returned wrong result.\nExpected %x,\ngot: %x)", sum, expSum)
	}
	// Test that checksummer.Sum appends correctly
	sum = checksummer.Sum(sum)
	expSum2 := append(expSum, expSum...)
	if !bytes.Equal(sum, expSum2) {
		t.Errorf("Checksum Sum method call 2 returned wrong result.\nExpected %x,\ngot: %x)", sum, expSum2)
	}
}

func TestUnalignedWrite(t *testing.T) {
	h := New()
	// "hello" = "hell" (0x6c6c6568) + "o" (0x6f)
	// Block 1: 0x6c6c6568
	// Block 2 (padded): 0x0000006f
	//
	// sum[0] = 0x6c6c6568 + 0x6f = 0x6c6c65d7
	// sum[1] = 0x6c6c6568 + 0x6c6c65d7 = 0xd8d8cb3f
	// sum[2] = 0x6c6c6568 + 0xd8d8cb3f = 0x1454530a7
	// sum[3] = 0x6c6c6568 + 0x1454530a7 = 0x1b1b1960f

	_, err := h.Write([]byte("hello"))
	if err != nil {
		t.Errorf("Write failed: %v", err)
	}

	exp := hexRes{"6c6c65d7", "d8d8cb3f", "1454530a7", "1b1b1960f"}
	res := h.Sum64x4()
	compare(t, "Unaligned write test", exp, res)
}

func TestReset(t *testing.T) {
	h := New()
	h.Write([]byte("123"))
	h.Reset()
	h.Write([]byte("4"))

	// "4" (0x34) padded to 4 bytes: 0x34, 0x00, 0x00, 0x00
	// uint32 value: 0x00000034 = 52
	// sum[0] = 52, sum[1] = 52, sum[2] = 52, sum[3] = 52
	exp := hexRes{"34", "34", "34", "34"}
	res := h.Sum64x4()
	compare(t, "Reset test", exp, res)
}

func TestUnalignedWrite2(t *testing.T) {
	inp1 := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	exp1 := hexRes{"c0a0806", "100d0a07", "14100c08", "18130e09"}

	checksummer := New()
	if _, err := checksummer.Write(inp1[:1]); err != nil {
		t.Fatal(err)
	}
	if _, err := checksummer.Write(inp1[1:3]); err != nil {
		t.Fatal(err)
	}
	if _, err := checksummer.Write(inp1[3:]); err != nil {
		t.Fatal(err)
	}

	res1 := checksummer.Sum64x4()
	compare(t, "Unaligned write test 2, 8 bytes written failed", exp1, res1)

	inp2 := []byte{2, 4, 6, 8}
	exp2 := hexRes{"14100c08", "241d160f", "382d2217", "50403020"}
	if _, err := checksummer.Write(inp2[:2]); err != nil {
		t.Fatal(err)
	}
	if _, err := checksummer.Write(inp2[2:]); err != nil {
		t.Fatal(err)
	}
	res2 := checksummer.Sum64x4()
	compare(t, "Unaligned write test 2, 12 bytes written failed", exp2, res2)

	var sum []byte
	sum = checksummer.Sum(sum)
	expSum := []byte{8, 12, 16, 20, 0, 0, 0, 0, 15, 22, 29, 36, 0, 0, 0, 0, 23, 34, 45, 56, 0, 0, 0, 0, 32, 48, 64, 80, 0, 0, 0, 0}
	if !bytes.Equal(sum, expSum) {
		t.Errorf("Checksum Sum method call 1 returned wrong result.\nExpected %x,\ngot: %x)", sum, expSum)
	}
	// Test that checksummer.Sum appends correctly
	sum = checksummer.Sum(sum)
	expSum2 := append(expSum, expSum...)
	if !bytes.Equal(sum, expSum2) {
		t.Errorf("Checksum Sum method call 2 returned wrong result.\nExpected %x,\ngot: %x)", sum, expSum2)
	}
}
