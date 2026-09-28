// journal.go — the systemd journal file-format reader: header, entry-array
// chain, entries, and data payloads with their XZ/LZ4/ZSTD compression.
// Clean-room from the documented format (systemd's journal-file layout doc);
// every offset and size is bounds-checked so a dirty or truncated journal
// yields what is readable, never a fault.
package journal

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"

	"github.com/klauspost/compress/zstd"
	lz4 "github.com/pierrec/lz4/v4"
	"github.com/ulikunitz/xz"
)

var journalMagic = []byte("LPKSHHRH")

// incompatible-flag bits.
const (
	fCompressedXZ   = 1 << 0
	fCompressedLZ4  = 1 << 1
	fKeyedHash      = 1 << 2
	fCompressedZSTD = 1 << 3
	fCompact        = 1 << 4

	knownIncompatible = fCompressedXZ | fCompressedLZ4 | fKeyedHash | fCompressedZSTD | fCompact
)

// object types.
const (
	objData       = 1
	objEntry      = 3
	objEntryArray = 6
)

// object flag bits (compression of a DATA payload).
const (
	objFlagXZ   = 1 << 0
	objFlagLZ4  = 1 << 1
	objFlagZSTD = 1 << 2
)

// caps that bound work on hostile or corrupt files.
const (
	maxDataPayload   = 256 * 1024 // per DATA object, compressed or not
	maxEntryItems    = 4096       // fields per entry
	maxArrayChain    = 1 << 20    // ENTRY_ARRAY chain links
	maxEntriesPerRun = 50_000_000 // absolute entry cap per file
)

type journalHeader struct {
	incompatible uint32
	state        uint8
	machineID    string
	entryArray   uint64
	nEntries     uint64
	headerSize   uint64
	compact      bool
}

type journalFile struct {
	r    io.ReaderAt
	size int64
	hdr  journalHeader
	zstd *zstd.Decoder
}

// openJournal validates the header of a journal held in r.
func openJournal(r io.ReaderAt, size int64) (*journalFile, error) {
	if size < 240 {
		return nil, fmt.Errorf("too small for a journal header (%d bytes)", size)
	}
	head := make([]byte, 240)
	if _, err := r.ReadAt(head, 0); err != nil {
		return nil, err
	}
	if !bytes.Equal(head[0:8], journalMagic) {
		return nil, fmt.Errorf("not a journal file (bad signature)")
	}
	le := binary.LittleEndian
	h := journalHeader{
		incompatible: le.Uint32(head[12:16]),
		state:        head[16],
		machineID:    hex.EncodeToString(head[40:56]),
		headerSize:   le.Uint64(head[88:96]),
		entryArray:   le.Uint64(head[176:184]),
		nEntries:     le.Uint64(head[152:160]),
	}
	if h.incompatible&^uint32(knownIncompatible) != 0 {
		return nil, fmt.Errorf("unknown incompatible flags %#x", h.incompatible)
	}
	h.compact = h.incompatible&fCompact != 0
	zd, err := zstd.NewReader(nil, zstd.WithDecoderMaxMemory(maxDataPayload))
	if err != nil {
		return nil, err
	}
	return &journalFile{r: r, size: size, hdr: h, zstd: zd}, nil
}

func (j *journalFile) close() { j.zstd.Close() }

// readAt bounds-checks and reads n bytes at off.
func (j *journalFile) readAt(off uint64, n int) ([]byte, error) {
	if n < 0 || off > uint64(j.size) || uint64(n) > uint64(j.size)-off {
		return nil, fmt.Errorf("object at %#x+%d beyond file end", off, n)
	}
	b := make([]byte, n)
	if _, err := j.r.ReadAt(b, int64(off)); err != nil {
		return nil, err
	}
	return b, nil
}

// objectHeader reads one object header, returning type, flags and the
// payload size (object size minus the 16-byte header).
func (j *journalFile) objectHeader(off uint64) (typ, flags byte, payload uint64, err error) {
	b, err := j.readAt(off, 16)
	if err != nil {
		return 0, 0, 0, err
	}
	size := binary.LittleEndian.Uint64(b[8:16])
	if size < 16 {
		return 0, 0, 0, fmt.Errorf("object at %#x with size %d", off, size)
	}
	return b[0], b[1], size - 16, nil
}

// entry is one decoded journal entry.
type entry struct {
	seqnum    uint64
	realtime  uint64 // µs
	monotonic uint64
	bootID    string
	fields    [][]byte // raw "KEY=value" payloads, in item order
	truncated bool     // some data payloads were capped or unreadable
}

// entryOffsets walks the main entry-array chain, calling fn per entry offset.
func (j *journalFile) entryOffsets(fn func(off uint64) error) error {
	arr := j.hdr.entryArray
	seen := 0
	total := uint64(0)
	for arr != 0 {
		seen++
		if seen > maxArrayChain {
			return fmt.Errorf("entry-array chain too long")
		}
		typ, _, payload, err := j.objectHeader(arr)
		if err != nil {
			return err
		}
		if typ != objEntryArray {
			return fmt.Errorf("object at %#x is type %d, want ENTRY_ARRAY", arr, typ)
		}
		if payload < 8 || payload > maxDataPayload*64 {
			return fmt.Errorf("entry array at %#x payload %d", arr, payload)
		}
		b, err := j.readAt(arr+16, int(payload))
		if err != nil {
			return err
		}
		le := binary.LittleEndian
		next := le.Uint64(b[0:8])
		items := b[8:]
		step := 8
		if j.hdr.compact {
			step = 4
		}
		for i := 0; i+step <= len(items); i += step {
			var off uint64
			if j.hdr.compact {
				off = uint64(le.Uint32(items[i : i+4]))
			} else {
				off = le.Uint64(items[i : i+8])
			}
			if off == 0 {
				continue
			}
			total++
			if total > maxEntriesPerRun {
				return fmt.Errorf("entry cap reached")
			}
			if err := fn(off); err != nil {
				return err
			}
		}
		arr = next
	}
	return nil
}

// readEntry decodes one ENTRY object and its data payloads.
func (j *journalFile) readEntry(off uint64) (*entry, error) {
	typ, _, payload, err := j.objectHeader(off)
	if err != nil {
		return nil, err
	}
	if typ != objEntry || payload < 48 {
		return nil, fmt.Errorf("object at %#x is not an entry", off)
	}
	if payload > maxDataPayload*64 {
		return nil, fmt.Errorf("entry at %#x payload %d", off, payload)
	}
	b, err := j.readAt(off+16, int(payload))
	if err != nil {
		return nil, err
	}
	le := binary.LittleEndian
	e := &entry{
		seqnum:    le.Uint64(b[0:8]),
		realtime:  le.Uint64(b[8:16]),
		monotonic: le.Uint64(b[16:24]),
		bootID:    hex.EncodeToString(b[24:40]),
	}
	items := b[48:]
	step := 16 // {object_offset u64, hash u64}
	if j.hdr.compact {
		step = 4 // {object_offset u32}
	}
	n := 0
	for i := 0; i+step <= len(items) && n < maxEntryItems; i += step {
		var doff uint64
		if j.hdr.compact {
			doff = uint64(le.Uint32(items[i : i+4]))
		} else {
			doff = le.Uint64(items[i : i+8])
		}
		if doff == 0 {
			continue
		}
		n++
		data, err := j.readData(doff)
		if err != nil {
			e.truncated = true
			continue // a dirty tail or an over-cap value: keep what is readable
		}
		e.fields = append(e.fields, data)
	}
	return e, nil
}

// readData decodes one DATA object's payload, decompressing as flagged.
// A value over maxDataPayload — as stored or once decompressed — comes
// back as an error, never as a silent prefix: readEntry drops that field
// and marks the entry Truncated, one rule for all four codecs.
func (j *journalFile) readData(off uint64) ([]byte, error) {
	typ, flags, payload, err := j.objectHeader(off)
	if err != nil {
		return nil, err
	}
	if typ != objData {
		return nil, fmt.Errorf("object at %#x is type %d, want DATA", off, typ)
	}
	head := uint64(48)
	if j.hdr.compact {
		head += 8
	}
	if payload < head {
		return nil, fmt.Errorf("data at %#x payload %d", off, payload)
	}
	n := payload - head
	if n > maxDataPayload {
		return nil, fmt.Errorf("data at %#x: stored payload %d over cap", off, n)
	}
	raw, err := j.readAt(off+16+head, int(n))
	if err != nil {
		return nil, err
	}
	switch {
	case flags&objFlagXZ != 0:
		zr, err := xz.NewReader(bytes.NewReader(raw))
		if err != nil {
			return nil, err
		}
		// One byte past the cap distinguishes over-cap from exactly-cap.
		out, err := io.ReadAll(io.LimitReader(zr, maxDataPayload+1))
		if err != nil {
			return nil, err
		}
		if len(out) > maxDataPayload {
			return nil, fmt.Errorf("xz data at %#x: decompressed over cap", off)
		}
		return out, nil
	case flags&objFlagLZ4 != 0:
		if len(raw) < 8 {
			return nil, fmt.Errorf("bad lz4 payload")
		}
		usize := binary.LittleEndian.Uint64(raw[0:8])
		if usize > maxDataPayload {
			return nil, fmt.Errorf("lz4 data at %#x: decompressed size %d over cap", off, usize)
		}
		out := make([]byte, usize)
		m, err := lz4.UncompressBlock(raw[8:], out)
		if err != nil {
			return nil, err
		}
		return out[:m], nil
	case flags&objFlagZSTD != 0:
		// Expansion is bounded at construction: the shared decoder carries
		// WithDecoderMaxMemory(maxDataPayload), so a frame growing past the
		// cap errors here instead of allocating.
		return j.zstd.DecodeAll(raw, nil)
	default:
		return raw, nil
	}
}
