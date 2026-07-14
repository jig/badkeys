package badkeys

import (
	"bytes"
	"io"
	"os"
	"strings"
)

// lookupPath finds the key path associated with the truncated hash key in a
// sorted lookup.txt file, using an on-disk binary search. It returns an empty
// string (and nil error) when the key is not present.
func lookupPath(file, key string) (string, error) {
	f, err := os.Open(file)
	if err != nil {
		return "", err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return "", err
	}
	size := fi.Size()

	lo, hi := int64(0), size
	for lo < hi {
		mid := (lo + hi) / 2
		start := lineStart(f, mid)
		lineKey, _, end, err := readLine(f, start)
		if err != nil {
			return "", err
		}
		if lineKey < key {
			lo = end
		} else {
			hi = start
		}
	}
	// lo is the start of the first line with key >= target
	if lo >= size {
		return "", nil
	}
	lineKey, path, _, err := readLine(f, lo)
	if err != nil {
		return "", err
	}
	if lineKey == key {
		return path, nil
	}
	return "", nil
}

// lineStart returns the offset of the start of the line containing pos.
func lineStart(f *os.File, pos int64) int64 {
	if pos <= 0 {
		return 0
	}
	const win = 512
	off := pos
	buf := make([]byte, win)
	for off > 0 {
		readAt := off - win
		if readAt < 0 {
			readAt = 0
		}
		n, err := f.ReadAt(buf[:off-readAt], readAt)
		if err != nil && err != io.EOF {
			return 0
		}
		if idx := bytes.LastIndexByte(buf[:n], '\n'); idx >= 0 {
			return readAt + int64(idx) + 1
		}
		off = readAt
		if readAt == 0 {
			break
		}
	}
	return 0
}

// readLine reads the line starting at start and splits it into the hash key
// (before ';') and the path (after). end is the offset just past the newline.
func readLine(f *os.File, start int64) (key, path string, end int64, err error) {
	const chunk = 4096
	var line []byte
	off := start
	buf := make([]byte, chunk)
	for {
		n, rerr := f.ReadAt(buf, off)
		if n > 0 {
			if idx := bytes.IndexByte(buf[:n], '\n'); idx >= 0 {
				line = append(line, buf[:idx]...)
				end = off + int64(idx) + 1
				break
			}
			line = append(line, buf[:n]...)
			off += int64(n)
		}
		if rerr == io.EOF {
			end = off
			break
		}
		if rerr != nil {
			return "", "", 0, rerr
		}
	}
	s := string(line)
	if i := strings.IndexByte(s, ';'); i >= 0 {
		return s[:i], s[i+1:], end, nil
	}
	return s, "", end, nil
}
