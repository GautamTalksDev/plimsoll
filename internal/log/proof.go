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

//go:build !js

package log

import (
	"fmt"
)

// InclusionProof returns an RFC 6962 inclusion proof for global idx.
func (l *Log) InclusionProof(idx int64) (InclusionProof, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	leaves, err := l.leafHashesLocked()
	if err != nil {
		return InclusionProof{}, err
	}
	n := int64(len(leaves))
	if n == 0 {
		return InclusionProof{}, errEmptyTree
	}
	if idx < 0 || idx >= n {
		return InclusionProof{}, fmt.Errorf("%w: %d (size %d)", errBadIndex, idx, n)
	}

	audit, err := InclusionAuditPath(int(idx), leaves)
	if err != nil {
		return InclusionProof{}, err
	}
	root := MerkleRoot(leaves)
	leaf := append([]byte(nil), leaves[idx]...)
	return InclusionProof{
		Index:     idx,
		TreeSize:  n,
		LeafHash:  leaf,
		AuditPath: audit,
		RootHash:  root,
	}, nil
}

// ConsistencyProof returns an RFC 6962 consistency proof between oldSize and
// newSize. newSize must equal the current tree size.
func (l *Log) ConsistencyProof(oldSize, newSize int64) (ConsistencyProof, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	leaves, err := l.leafHashesLocked()
	if err != nil {
		return ConsistencyProof{}, err
	}
	n := int64(len(leaves))
	if newSize != n {
		return ConsistencyProof{}, fmt.Errorf("%w: newSize %d != current %d", errBadTreeSize, newSize, n)
	}
	if oldSize < 0 || oldSize > newSize {
		return ConsistencyProof{}, errBadTreeSize
	}

	audit, err := ConsistencyAuditPath(int(oldSize), int(newSize), leaves)
	if err != nil {
		return ConsistencyProof{}, err
	}

	var oldRoot []byte
	if oldSize == 0 {
		oldRoot = EmptyRoot()
	} else {
		oldRoot = MerkleRoot(leaves[:oldSize])
	}
	newRoot := MerkleRoot(leaves)

	return ConsistencyProof{
		OldSize:   oldSize,
		NewSize:   newSize,
		OldRoot:   oldRoot,
		NewRoot:   newRoot,
		AuditPath: audit,
	}, nil
}
