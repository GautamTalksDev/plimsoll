// Copyright 2026 The PLIMSOLL Authors
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

package log

import "github.com/GautamTalksDev/plimsoll/internal/logmerkle"

// LeafHash returns SHA-256(0x00 || entry) per RFC 6962 domain separation.
func LeafHash(entry []byte) []byte { return logmerkle.LeafHash(entry) }

// NodeHash returns SHA-256(0x01 || left || right) per RFC 6962.
func NodeHash(left, right []byte) []byte { return logmerkle.NodeHash(left, right) }

// EmptyRoot returns the RFC 6962 hash of an empty Merkle tree.
func EmptyRoot() []byte { return logmerkle.EmptyRoot() }

// MerkleRoot computes the RFC 6962 Merkle Tree Hash over leaf hashes.
func MerkleRoot(leafHashes [][]byte) []byte { return logmerkle.MerkleRoot(leafHashes) }

// InclusionAuditPath returns the RFC 6962 Merkle audit path for leafIdx.
func InclusionAuditPath(leafIdx int, leafHashes [][]byte) ([][]byte, error) {
	return logmerkle.InclusionAuditPath(leafIdx, leafHashes)
}

// ConsistencyAuditPath returns PROOF(oldSize, D[newSize]) per RFC 6962.
func ConsistencyAuditPath(oldSize, newSize int, leafHashes [][]byte) ([][]byte, error) {
	return logmerkle.ConsistencyAuditPath(oldSize, newSize, leafHashes)
}

// VerifyInclusion checks a Merkle inclusion proof against root.
func VerifyInclusion(leafIdx, treeSize int, leafHash []byte, auditPath [][]byte, root []byte) bool {
	return logmerkle.VerifyInclusion(leafIdx, treeSize, leafHash, auditPath, root)
}

// VerifyConsistency checks a consistency proof between two tree sizes.
func VerifyConsistency(oldSize, newSize int, oldRoot, newRoot []byte, proof [][]byte) bool {
	return logmerkle.VerifyConsistency(oldSize, newSize, oldRoot, newRoot, proof)
}
