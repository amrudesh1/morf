/*
Copyright [2023] [Amrudesh Balakrishnan]

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package utils

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"

	log "github.com/sirupsen/logrus"
)

// hashCacheEntry holds a cached hash result alongside the file metadata used
// to detect stale entries.
type hashCacheEntry struct {
	hash    string
	size    int64
	modTime int64 // UnixNano
}

// hashFileCache is the package-level memoisation store.
var hashFileCache sync.Map // key: absolute path → hashCacheEntry

// HashFileCached returns the SHA-256 hash (first 16 bytes, hex-encoded) of the
// file at path. The result is memoised by (absolute path, size, modtime) so
// repeated calls within one scan compute the digest only once.
func HashFileCached(path string) (string, error) {
	absPath, err := filepath.Abs(path)
	if err != nil {
		absPath = path
	}

	info, err := os.Stat(absPath)
	if err != nil {
		return "", fmt.Errorf("HashFileCached: stat %s: %w", absPath, err)
	}
	size := info.Size()
	modTime := info.ModTime().UnixNano()

	if v, ok := hashFileCache.Load(absPath); ok {
		e := v.(hashCacheEntry)
		if e.size == size && e.modTime == modTime {
			return e.hash, nil
		}
	}

	f, err := os.Open(absPath)
	if err != nil {
		return "", fmt.Errorf("HashFileCached: open %s: %w", absPath, err)
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", fmt.Errorf("HashFileCached: read %s: %w", absPath, err)
	}
	result := hex.EncodeToString(h.Sum(nil)[:16])

	hashFileCache.Store(absPath, hashCacheEntry{hash: result, size: size, modTime: modTime})
	return result, nil
}

// ExtractHash calculates the SHA-256 hash of a file
func ExtractHash(filePath string) string {
	file, err := os.Open(filePath)
	if err != nil {
		log.Error("Error opening file for hashing:", err)
		return ""
	}
	defer file.Close()

	hash := sha256.New()

	if _, err := io.Copy(hash, file); err != nil {
		log.Error("Error calculating file hash:", err)
		return ""
	}

	return hex.EncodeToString(hash.Sum(nil)[:16])
}
