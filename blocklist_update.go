package badkeys

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"

	"github.com/ulikunitz/xz"
)

// UpdateURL is the base URL for blocklist downloads.
const UpdateURL = "https://update.badkeys.info"

// bkFormat is the blocklist format version this port supports.
const bkFormat = 0

// UpdateOptions controls a blocklist update.
type UpdateOptions struct {
	// Dir is the cache directory to write to. Empty means CacheDir().
	Dir string
	// Lookup also downloads the (large) lookup.txt file for URL resolution.
	Lookup bool
	// Log, if set, receives human-readable progress messages.
	Log func(string)
}

// UpdateBlocklist downloads (or refreshes) the blocklist data into the cache
// directory. It fetches badkeysdata.json and blocklist.dat, and optionally
// lookup.txt. Files are only re-downloaded when their hash changed.
func UpdateBlocklist(opts UpdateOptions) error {
	dir := opts.Dir
	if dir == "" {
		dir = CacheDir()
	}
	logf := func(format string, a ...any) {
		if opts.Log != nil {
			opts.Log(fmt.Sprintf(format, a...))
		}
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}

	jurl := fmt.Sprintf("%s/v%d/badkeysdata.json", UpdateURL, bkFormat)
	raw, err := httpGet(jurl)
	if err != nil {
		return fmt.Errorf("fetching metadata: %w", err)
	}
	var bk bkData
	if err := json.Unmarshal(raw, &bk); err != nil {
		return fmt.Errorf("parsing metadata: %w", err)
	}
	if bk.BKFormat != bkFormat {
		return fmt.Errorf("unexpected blocklist format %d", bk.BKFormat)
	}
	if bk.BlocklistURL == "" {
		return fmt.Errorf("blocklist no longer available in requested format")
	}

	jsonPath := filepath.Join(dir, "badkeysdata.json")
	if old, _ := os.ReadFile(jsonPath); string(old) != string(raw) {
		logf("Writing new badkeysdata.json...")
		if err := os.WriteFile(jsonPath, raw, 0o644); err != nil {
			return err
		}
	} else {
		logf("No new metadata")
	}

	if fileSHA256(filepath.Join(dir, "blocklist.dat")) != bk.BlocklistSHA256 {
		logf("Downloading blocklist.dat...")
		if err := downloadXZ(bk.BlocklistURL, filepath.Join(dir, "blocklist.dat"), bk.BlocklistSHA256); err != nil {
			return err
		}
	}

	if opts.Lookup && fileSHA256(filepath.Join(dir, "lookup.txt")) != bk.LookupSHA256 {
		logf("Downloading lookup.txt...")
		if err := downloadXZ(bk.LookupURL, filepath.Join(dir, "lookup.txt"), bk.LookupSHA256); err != nil {
			return err
		}
	}
	return nil
}

func httpGet(url string) ([]byte, error) {
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: %s", url, resp.Status)
	}
	return io.ReadAll(resp.Body)
}

// downloadXZ downloads an xz-compressed file, decompresses it, verifies its
// SHA-256, and atomically writes it to dst.
func downloadXZ(url, dst, expSHA string) error {
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GET %s: %s", url, resp.Status)
	}
	xr, err := xz.NewReader(resp.Body)
	if err != nil {
		return err
	}
	data, err := io.ReadAll(xr)
	if err != nil {
		return err
	}
	if got := sha256Hex(data); got != expSHA {
		return fmt.Errorf("SHA256 mismatch for %s: got %s, want %s", filepath.Base(dst), got, expSHA)
	}
	tmp := dst + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, dst)
}

func fileSHA256(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return sha256Hex(data)
}

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
