// Package archiveio centralizes resource limits for data read from ZIP/JAR
// files. Archive metadata is untrusted even when the archive came from a local
// build: a corrupt dependency must not turn one editor request into an
// unbounded allocation.
package archiveio

import (
	"archive/zip"
	"compress/flate"
	"context"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
)

const (
	// MaxEntryBytes accommodates unusually large generated sources and class
	// files while keeping one archive member from consuming the editor's heap.
	MaxEntryBytes int64 = 64 << 20
	// MaxMetadataBytes is for manifests and other small control entries.
	MaxMetadataBytes          int64  = 1 << 20
	MaxEntryCompressedBytes   uint64 = 64 << 20
	MaxArchiveEntries                = 250000
	MaxArchiveExpandedBytes   uint64 = 2 << 30
	MaxArchiveCompressedBytes uint64 = 2 << 30
	MaxCompressionRatio       uint64 = 1000
)

var (
	ErrEntryTooLarge = errors.New("archive entry exceeds size limit")
	ErrArchiveBudget = errors.New("archive exceeds aggregate safety budget")
)

// Budget accounts bytes that are actually produced while selected members of
// one archive are decompressed. The central-directory validation is necessary
// but insufficient: corrupt size fields must not reset the aggregate limit for
// every member a caller chooses to read.
type Budget struct {
	gate       chan struct{}
	expanded   uint64
	compressed uint64
}

// NewBudget validates the central directory and creates the one budget that
// must be shared by all reads from this archive.
func NewBudget(files []*zip.File) (*Budget, error) {
	if err := ValidateZipFiles(files); err != nil {
		return nil, err
	}
	gate := make(chan struct{}, 1)
	gate <- struct{}{}
	return &Budget{gate: gate}, nil
}

func compressionRatioExceeds(expanded, compressed, limit uint64) bool {
	if compressed == 0 {
		return expanded > 0
	}
	quotient := expanded / compressed
	return quotient > limit || quotient == limit && expanded%compressed != 0
}

// ValidateZipFiles rejects archives whose central directory or declared total
// expansion is itself unreasonable. It must be called once after OpenReader,
// before consumers enumerate selected members.
func ValidateZipFiles(files []*zip.File) error {
	if len(files) > MaxArchiveEntries {
		return fmt.Errorf("%w: %d entries (limit %d)", ErrArchiveBudget, len(files), MaxArchiveEntries)
	}
	var expanded, compressed uint64
	for _, file := range files {
		if file == nil {
			continue
		}
		if file.Method != zip.Store && file.Method != zip.Deflate {
			return fmt.Errorf("%w: %s uses unsupported compression method %d", ErrArchiveBudget, file.Name, file.Method)
		}
		if file.UncompressedSize64 > MaxArchiveExpandedBytes-expanded {
			return fmt.Errorf("%w: declared expansion exceeds %d bytes", ErrArchiveBudget, MaxArchiveExpandedBytes)
		}
		expanded += file.UncompressedSize64
		if file.CompressedSize64 > MaxEntryCompressedBytes {
			return fmt.Errorf("%w: %s declares %d compressed bytes (entry limit %d)", ErrArchiveBudget, file.Name, file.CompressedSize64, MaxEntryCompressedBytes)
		}
		if file.CompressedSize64 > MaxArchiveCompressedBytes-compressed {
			return fmt.Errorf("%w: declared compressed input exceeds %d bytes", ErrArchiveBudget, MaxArchiveCompressedBytes)
		}
		compressed += file.CompressedSize64
		if file.UncompressedSize64 > uint64(MaxMetadataBytes) {
			compressed := file.CompressedSize64
			if compressionRatioExceeds(file.UncompressedSize64, compressed, MaxCompressionRatio) {
				return fmt.Errorf("%w: %s declares compression ratio above %d:1", ErrArchiveBudget, file.Name, MaxCompressionRatio)
			}
		}
	}
	return nil
}

type countingByteReader struct {
	reader    io.Reader
	ctx       context.Context
	remaining uint64
	read      uint64
}

func (reader *countingByteReader) Read(buffer []byte) (int, error) {
	if err := reader.ctx.Err(); err != nil {
		return 0, err
	}
	if reader.remaining == 0 {
		return 0, ErrArchiveBudget
	}
	if uint64(len(buffer)) > reader.remaining {
		buffer = buffer[:reader.remaining]
	}
	read, err := reader.reader.Read(buffer)
	reader.read += uint64(read)
	reader.remaining -= uint64(read)
	return read, err
}

// Read reads one member under both its entry limit and this archive's remaining
// actual expansion budget. Its ratio check uses bytes produced by the
// decompressor rather than trusting UncompressedSize64.
func (budget *Budget) Read(file *zip.File, limit int64) ([]byte, error) {
	return budget.ReadContext(context.Background(), file, limit)
}

// ReadContext is Read with cancellation propagated through the raw compressed
// stream. Its gate is context-aware as well, so one slow archive member cannot
// leave later foreground requests stuck waiting for the shared budget lock.
func (budget *Budget) ReadContext(ctx context.Context, file *zip.File, limit int64) ([]byte, error) {
	if budget == nil {
		return nil, errors.New("nil archive budget")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-budget.gate:
	}
	defer func() { budget.gate <- struct{}{} }()
	if file == nil {
		return nil, errors.New("nil archive entry")
	}
	if limit < 0 {
		return nil, errors.New("negative archive entry limit")
	}
	if limit > MaxEntryBytes {
		return nil, fmt.Errorf("archive entry limit exceeds global maximum %d", MaxEntryBytes)
	}
	if file.UncompressedSize64 > uint64(limit) {
		return nil, fmt.Errorf("%w: %s declares %d bytes (limit %d)", ErrEntryTooLarge, file.Name, file.UncompressedSize64, limit)
	}
	if compressionRatioExceeds(file.UncompressedSize64, file.CompressedSize64, MaxCompressionRatio) {
		return nil, fmt.Errorf("%w: %s declares compression ratio above %d:1", ErrArchiveBudget, file.Name, MaxCompressionRatio)
	}
	if budget.expanded >= MaxArchiveExpandedBytes {
		return nil, fmt.Errorf("%w: actual expansion exceeds %d bytes", ErrArchiveBudget, MaxArchiveExpandedBytes)
	}
	if file.CompressedSize64 > MaxEntryCompressedBytes || budget.compressed >= MaxArchiveCompressedBytes {
		return nil, fmt.Errorf("%w: compressed input exceeds its safety budget", ErrArchiveBudget)
	}
	remaining := MaxArchiveExpandedBytes - budget.expanded
	streamLimit := uint64(limit)
	if remaining < streamLimit {
		streamLimit = remaining
	}
	raw, err := file.OpenRaw()
	if err != nil {
		return nil, err
	}
	compressedLimit := MaxEntryCompressedBytes
	if remainingArchive := MaxArchiveCompressedBytes - budget.compressed; remainingArchive < compressedLimit {
		compressedLimit = remainingArchive
	}
	compressed := &countingByteReader{reader: raw, ctx: ctx, remaining: compressedLimit}
	defer func() {
		if compressed.read > MaxArchiveCompressedBytes-budget.compressed {
			budget.compressed = MaxArchiveCompressedBytes
		} else {
			budget.compressed += compressed.read
		}
	}()
	var reader io.ReadCloser
	switch file.Method {
	case zip.Store:
		reader = io.NopCloser(compressed)
	case zip.Deflate:
		reader = flate.NewReader(compressed)
	default:
		return nil, fmt.Errorf("%w: %s uses unsupported compression method %d", ErrArchiveBudget, file.Name, file.Method)
	}
	checksum := crc32.NewIEEE()
	limited := &io.LimitedReader{R: io.TeeReader(reader, checksum), N: int64(streamLimit) + 1}
	data, readErr := io.ReadAll(limited)
	closeErr := reader.Close()
	actual := uint64(len(data))
	if actual > remaining {
		budget.expanded = MaxArchiveExpandedBytes
		return nil, fmt.Errorf("%w: %s took actual expansion above %d bytes", ErrArchiveBudget, file.Name, MaxArchiveExpandedBytes)
	}
	budget.expanded += actual
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("%w: %s expanded beyond %d bytes", ErrEntryTooLarge, file.Name, limit)
	}
	if actual <= streamLimit && compressed.read < file.CompressedSize64 {
		var trailing [1]byte
		if count, trailingErr := compressed.Read(trailing[:]); count != 0 || trailingErr != io.EOF {
			return nil, fmt.Errorf("%w: %s has trailing or unread compressed data", ErrArchiveBudget, file.Name)
		}
	}
	if compressed.read != file.CompressedSize64 {
		return nil, fmt.Errorf("%w: %s consumed %d compressed bytes but declared %d", ErrArchiveBudget, file.Name, compressed.read, file.CompressedSize64)
	}
	if compressionRatioExceeds(actual, compressed.read, MaxCompressionRatio) {
		return nil, fmt.Errorf("%w: %s actual compression ratio exceeds %d:1", ErrArchiveBudget, file.Name, MaxCompressionRatio)
	}
	if readErr != nil {
		return nil, readErr
	}
	if closeErr != nil {
		return nil, closeErr
	}
	if actual != file.UncompressedSize64 {
		return nil, fmt.Errorf("%w: %s produced %d bytes but declared %d", ErrArchiveBudget, file.Name, actual, file.UncompressedSize64)
	}
	if checksum.Sum32() != file.CRC32 {
		return nil, fmt.Errorf("%w: %s failed CRC validation", ErrArchiveBudget, file.Name)
	}
	return data, nil
}

// ReadZipFile is the single-member convenience form. Archive enumerators must
// use NewBudget and share Budget.Read across the whole archive.
func ReadZipFile(file *zip.File, limit int64) ([]byte, error) {
	return ReadZipFileContext(context.Background(), file, limit)
}

func ReadZipFileContext(ctx context.Context, file *zip.File, limit int64) ([]byte, error) {
	budget, err := NewBudget([]*zip.File{file})
	if err != nil {
		return nil, err
	}
	return budget.ReadContext(ctx, file, limit)
}
