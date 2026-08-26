// Copyright 2026 The PLIMSOLL Authors
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package logmerkle implements pure RFC 6962 Merkle verification with no I/O.
package logmerkle

import (
	"crypto/sha256"
	"fmt"
)

const (
	leafPrefix byte = 0x00
	nodePrefix byte = 0x01
)

// LeafHash returns SHA-256(0x00 || entry) per RFC 6962 domain separation.
func LeafHash(entry []byte) []byte {
	h := sha256.New()
	h.Write([]byte{leafPrefix})
	h.Write(entry)
	return h.Sum(nil)
}

// NodeHash returns SHA-256(0x01 || left || right) per RFC 6962.
func NodeHash(left, right []byte) []byte {
	h := sha256.New()
	h.Write([]byte{nodePrefix})
	h.Write(left)
	h.Write(right)
	return h.Sum(nil)
}

var emptyRoot = sha256.Sum256(nil)

// EmptyRoot returns the RFC 6962 hash of an empty Merkle tree.
func EmptyRoot() []byte {
	out := make([]byte, len(emptyRoot))
	copy(out, emptyRoot[:])
	return out
}

// MerkleRoot computes the RFC 6962 Merkle Tree Hash over leaf hashes.
func MerkleRoot(leafHashes [][]byte) []byte {
	if len(leafHashes) == 0 {
		return EmptyRoot()
	}
	return mth(leafHashes)
}

func mth(leaves [][]byte) []byte {
	n := len(leaves)
	if n == 1 {
		out := make([]byte, len(leaves[0]))
		copy(out, leaves[0])
		return out
	}
	k := largestPowerOfTwoLessThan(n)
	return NodeHash(mth(leaves[0:k]), mth(leaves[k:n]))
}

func largestPowerOfTwoLessThan(n int) int {
	k := 1
	for (k << 1) < n {
		k <<= 1
	}
	return k
}

func isPowerOfTwo(n int) bool {
	return n > 0 && n&(n-1) == 0
}

// VerifyInclusion checks a Merkle inclusion proof against root.
func VerifyInclusion(leafIdx, treeSize int, leafHash []byte, auditPath [][]byte, root []byte) bool {
	if treeSize <= 0 || leafIdx < 0 || leafIdx >= treeSize {
		return false
	}
	got, ok := rootFromInclusionPath(leafIdx, treeSize, leafHash, auditPath)
	return ok && bytesEqual(got, root)
}

func rootFromInclusionPath(m, n int, hash []byte, path [][]byte) ([]byte, bool) {
	if n == 1 {
		return hash, len(path) == 0
	}
	if len(path) == 0 {
		return nil, false
	}
	k := largestPowerOfTwoLessThan(n)
	sibling := path[len(path)-1]
	rest := path[:len(path)-1]
	if m < k {
		left, ok := rootFromInclusionPath(m, k, hash, rest)
		if !ok {
			return nil, false
		}
		return NodeHash(left, sibling), true
	}
	right, ok := rootFromInclusionPath(m-k, n-k, hash, rest)
	if !ok {
		return nil, false
	}
	return NodeHash(sibling, right), true
}

// VerifyConsistency checks a consistency proof between two tree sizes.
func VerifyConsistency(oldSize, newSize int, oldRoot, newRoot []byte, proof [][]byte) bool {
	if oldSize < 0 || newSize < 0 || oldSize > newSize {
		return false
	}
	if oldSize == newSize {
		return bytesEqual(oldRoot, newRoot) && len(proof) == 0
	}
	if oldSize == 0 {
		return len(proof) == 0
	}
	if len(proof) == 0 {
		return false
	}
	if oldSize < 1 || newSize < 1 {
		return false
	}
	fn := uint64(oldSize - 1) //nolint:gosec // G115 -- guarded above
	sn := uint64(newSize - 1) //nolint:gosec // G115 -- guarded above

	var q [][]byte
	if isPowerOfTwo(oldSize) {
		q = make([][]byte, 0, len(proof)+1)
		q = append(q, append([]byte(nil), oldRoot...))
		q = append(q, proof...)
	} else {
		q = proof
	}

	for fn&1 == 1 {
		fn >>= 1
		sn >>= 1
	}

	fr := append([]byte(nil), q[0]...)
	sr := append([]byte(nil), q[0]...)

	for _, c := range q[1:] {
		if sn == 0 {
			return false
		}
		if fn&1 == 1 || fn == sn {
			fr = NodeHash(c, fr)
			sr = NodeHash(c, sr)
			for fn&1 == 0 && sn&1 == 1 {
				fn >>= 1
				sn >>= 1
			}
		} else {
			sr = NodeHash(sr, c)
		}
		fn >>= 1
		sn >>= 1
	}
	return sn == 0 && bytesEqual(fr, oldRoot) && bytesEqual(sr, newRoot)
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// InclusionAuditPath returns the RFC 6962 Merkle audit path for leafIdx.
func InclusionAuditPath(leafIdx int, leafHashes [][]byte) ([][]byte, error) {
	n := len(leafHashes)
	if n == 0 {
		return nil, fmt.Errorf("logmerkle: empty tree")
	}
	if leafIdx < 0 || leafIdx >= n {
		return nil, fmt.Errorf("logmerkle: leaf index out of range")
	}
	return path(leafIdx, leafHashes), nil
}

func path(m int, leaves [][]byte) [][]byte {
	n := len(leaves)
	if n == 1 {
		return nil
	}
	k := largestPowerOfTwoLessThan(n)
	if m < k {
		return append(path(m, leaves[0:k]), mth(leaves[k:n]))
	}
	return append(path(m-k, leaves[k:n]), mth(leaves[0:k]))
}

// ConsistencyAuditPath returns PROOF(oldSize, D[newSize]) per RFC 6962.
func ConsistencyAuditPath(oldSize, newSize int, leafHashes [][]byte) ([][]byte, error) {
	if newSize != len(leafHashes) {
		return nil, fmt.Errorf("logmerkle: newSize mismatch")
	}
	if oldSize < 0 || newSize < 0 || oldSize > newSize {
		return nil, fmt.Errorf("logmerkle: invalid tree size")
	}
	if oldSize == 0 || oldSize == newSize {
		return nil, nil
	}
	return subproof(oldSize, leafHashes, true), nil
}

func subproof(m int, leaves [][]byte, b bool) [][]byte {
	n := len(leaves)
	if m == n {
		if b {
			return nil
		}
		return [][]byte{mth(leaves)}
	}
	k := largestPowerOfTwoLessThan(n)
	if m <= k {
		return append(subproof(m, leaves[0:k], b), mth(leaves[k:n]))
	}
	return append(subproof(m-k, leaves[k:n], false), mth(leaves[0:k]))
}
