package badkeys

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// blMeta describes one source blocklist.
type blMeta struct {
	ID   int    `json:"id"`
	Name string `json:"name"`
	Type string `json:"type"`
	Repo string `json:"repo"`
	Path string `json:"path"`
}

// bkData is the parsed badkeysdata.json metadata file.
type bkData struct {
	BKFormat        int      `json:"bkformat"`
	Date            string   `json:"date"`
	BlocklistURL    string   `json:"blocklist_url"`
	BlocklistSHA256 string   `json:"blocklist_sha256"`
	LookupURL       string   `json:"lookup_url"`
	LookupSHA256    string   `json:"lookup_sha256"`
	Deprecated      any      `json:"deprecated"`
	Blocklists      []blMeta `json:"blocklists"`
}

// Blocklist is a loaded set of compromised-key hashes plus their metadata.
type Blocklist struct {
	data []byte         // sorted 16-byte blocks: 15-byte hash + 1-byte id
	meta map[int]blMeta // blocklist id -> metadata
	dir  string         // cache directory the blocklist was loaded from
}

var (
	defaultBLMu sync.RWMutex
	defaultBL   *Blocklist
)

// CacheDir returns the directory used to store blocklist data, honoring
// XDG_CACHE_HOME and defaulting to ~/.cache/badkeys.
func CacheDir() string {
	if x := os.Getenv("XDG_CACHE_HOME"); x != "" {
		return filepath.Join(x, "badkeys")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return filepath.Join(".cache", "badkeys")
	}
	return filepath.Join(home, ".cache", "badkeys")
}

// LoadBlocklist loads a blocklist from dir. If dir is empty, CacheDir is used.
// It reads badkeysdata.json and blocklist.dat, which must have been downloaded
// beforehand (see UpdateBlocklist).
func LoadBlocklist(dir string) (*Blocklist, error) {
	if dir == "" {
		dir = CacheDir()
	}
	metaRaw, err := os.ReadFile(filepath.Join(dir, "badkeysdata.json"))
	if err != nil {
		return nil, fmt.Errorf("blocklist metadata not found, run UpdateBlocklist: %w", err)
	}
	var bk bkData
	if err := json.Unmarshal(metaRaw, &bk); err != nil {
		return nil, fmt.Errorf("parsing badkeysdata.json: %w", err)
	}
	data, err := os.ReadFile(filepath.Join(dir, "blocklist.dat"))
	if err != nil {
		return nil, fmt.Errorf("blocklist.dat not found, run UpdateBlocklist: %w", err)
	}
	meta := map[int]blMeta{}
	for _, m := range bk.Blocklists {
		meta[m.ID] = m
	}
	return &Blocklist{data: data, meta: meta, dir: dir}, nil
}

// SetDefaultBlocklist installs bl as the blocklist used by the "blocklist"
// check. Passing nil disables the check.
func SetDefaultBlocklist(bl *Blocklist) {
	defaultBLMu.Lock()
	defaultBL = bl
	defaultBLMu.Unlock()
}

// LoadDefaultBlocklist loads the blocklist from dir (or CacheDir) and installs
// it as the default.
func LoadDefaultBlocklist(dir string) error {
	bl, err := LoadBlocklist(dir)
	if err != nil {
		return err
	}
	SetDefaultBlocklist(bl)
	return nil
}

// Lookup searches the blocklist for the given canonical key value and returns
// a finding if it is listed.
func (bl *Blocklist) Lookup(val []byte) *Finding {
	sum := sha256.Sum256(val)
	return bl.search(sum[:15])
}

func (bl *Blocklist) search(hash15 []byte) *Finding {
	blocks := len(bl.data) / 16
	lo, hi := 0, blocks-1
	for lo <= hi {
		mid := (lo + hi) / 2
		val := bl.data[mid*16 : mid*16+15]
		cmp := bytes.Compare(hash15, val)
		switch {
		case cmp == 0:
			blID := int(bl.data[mid*16+15])
			subtest := fmt.Sprintf("id%d", blID)
			if m, ok := bl.meta[blID]; ok {
				subtest = m.Name
			}
			return &Finding{
				Subtest: subtest,
				BlockID: blID,
				Lookup:  hex.EncodeToString(hash15[0:8]),
				Debug:   "Truncated Hash: " + hex.EncodeToString(hash15),
			}
		case cmp > 0:
			lo = mid + 1
		default:
			hi = mid - 1
		}
	}
	return nil
}

// blocklistCheck is the registered "blocklist" check. It uses the default
// blocklist if one is installed, otherwise it does nothing.
func blocklistCheck(val []byte) *Finding {
	defaultBLMu.RLock()
	bl := defaultBL
	defaultBLMu.RUnlock()
	if bl == nil {
		return nil
	}
	return bl.Lookup(val)
}

// URLLookup resolves a blocklist finding to the public URLs of the compromised
// key using the optional lookup.txt file in the blocklist's cache directory.
// It returns empty strings if the key is not found or lookup.txt is missing.
func (bl *Blocklist) URLLookup(blID int, lhash string) (showURL, rawURL string, err error) {
	m, ok := bl.meta[blID]
	if !ok {
		return "", "", fmt.Errorf("unknown blocklist id %d", blID)
	}
	path, err := lookupPath(filepath.Join(bl.dir, "lookup.txt"), lhash)
	if err != nil {
		return "", "", err
	}
	if path == "" {
		return "", "", nil
	}
	showURL = fmt.Sprintf("https://github.com/%s/blob/%s/%s", m.Repo, m.Path, path)
	rawURL = fmt.Sprintf("https://raw.githubusercontent.com/%s/%s/%s", m.Repo, m.Path, path)
	return showURL, rawURL, nil
}
