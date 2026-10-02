// Package formathost formats source through the build's own formatter --
// Spotless running ktlint -- in a warm JVM, so an editor's format request
// produces exactly what the build's format check accepts.
package formathost

import (
	"bufio"
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/shinyvision/kotlsp/internal/resourcebudget"
)

//go:embed KotlspFormatHost.java
var hostSource string

// Spec says how the build formats a file: the formatter's classpath, which
// includes Spotless's adapter, and its settings.
type Spec struct {
	Classpath    []string
	EditorConfig string
	Overrides    map[string]string
}

// idleShutdown is how long an unused host keeps its JVM. A format request
// after that pays the start-up again (well under a second for ktlint); a
// resident idle JVM would hold a few hundred megabytes for nothing.
const idleShutdown = 5 * time.Minute

// hostBytes is the host's -Xmx, reserved against the process tree's memory
// budget like every other child JVM.
const hostBytes int64 = 384 << 20

// Pool keeps one warm host per formatter classpath.
type Pool struct {
	mu     sync.Mutex
	hosts  map[string]*host
	closed bool
	// JavaHome selects the JVM; empty uses java from PATH.
	JavaHome string
}

type host struct {
	pool    *Pool
	key     string
	mu      sync.Mutex
	command *exec.Cmd
	stdin   io.WriteCloser
	stdout  *bufio.Reader
	release func()
	idle    *time.Timer
	dead    bool
}

// Format returns text formatted the way spec's formatter formats the file at
// path. The path matters: editorconfig sections and file kind follow it.
func (p *Pool) Format(ctx context.Context, spec Spec, path, text string) (string, error) {
	if len(spec.Classpath) == 0 {
		return "", errors.New("no formatter classpath")
	}
	h, err := p.host(ctx, spec)
	if err != nil {
		return "", err
	}
	// Spotless's adapter reads the file and then substitutes the text it was
	// given, so the path has to exist. A buffer not saved yet is formatted
	// as an empty file of the same name in kotlsp's own temporary directory.
	if !fileExists(path) {
		placeholder, placeholderErr := placeholderFile(filepath.Base(path))
		if placeholderErr != nil {
			return "", placeholderErr
		}
		path = placeholder
	}
	return h.format(ctx, spec, path, text)
}

func placeholderFile(name string) (string, error) {
	directory := filepath.Join(os.TempDir(), "kotlsp-format")
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return "", err
	}
	path := filepath.Join(directory, name)
	if !fileExists(path) {
		if err := os.WriteFile(path, nil, 0o600); err != nil {
			return "", err
		}
	}
	return path, nil
}

// Close stops every host.
func (p *Pool) Close() {
	p.mu.Lock()
	p.closed = true
	hosts := p.hosts
	p.hosts = nil
	p.mu.Unlock()
	for _, h := range hosts {
		h.mu.Lock()
		h.stop()
		h.mu.Unlock()
	}
}

func (p *Pool) host(ctx context.Context, spec Spec) (*host, error) {
	key := strings.Join(spec.Classpath, string(os.PathListSeparator))
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return nil, errors.New("formatter pool closed")
	}
	if h := p.hosts[key]; h != nil && !h.dead {
		return h, nil
	}
	h, err := p.start(ctx, key)
	if err != nil {
		return nil, err
	}
	if p.hosts == nil {
		p.hosts = make(map[string]*host)
	}
	p.hosts[key] = h
	return h, nil
}

func (p *Pool) start(ctx context.Context, classpath string) (*host, error) {
	java := "java"
	if p.JavaHome != "" {
		if candidate := filepath.Join(p.JavaHome, "bin", "java"); fileExists(candidate) {
			java = candidate
		}
	}
	directory, err := buildHost(ctx, p.JavaHome)
	if err != nil {
		return nil, err
	}
	reserveCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	release, err := resourcebudget.Acquire(reserveCtx, "format-host", hostBytes)
	if err != nil {
		return nil, err
	}
	command := exec.Command(java, "-Xmx384m", "-XX:+ExitOnOutOfMemoryError", "-XX:+UseSerialGC", "-XX:TieredStopAtLevel=1",
		"-cp", classpath+string(os.PathListSeparator)+directory, "KotlspFormatHost")
	configureProcess(command)
	stdin, err := command.StdinPipe()
	if err != nil {
		release()
		return nil, err
	}
	stdout, err := command.StdoutPipe()
	if err != nil {
		release()
		return nil, err
	}
	command.Stderr = io.Discard
	if err := command.Start(); err != nil {
		release()
		return nil, err
	}
	h := &host{pool: p, key: classpath, command: command, stdin: stdin, stdout: bufio.NewReaderSize(stdout, 1<<16), release: release}
	ready := make(chan error, 1)
	go func() {
		_, _, readErr := readFrame(h.stdout)
		ready <- readErr
	}()
	select {
	case err = <-ready:
	case <-time.After(30 * time.Second):
		err = errors.New("the formatter host did not start within 30s")
	case <-ctx.Done():
		err = ctx.Err()
	}
	if err != nil {
		h.stop()
		return nil, fmt.Errorf("starting the formatter host: %w", err)
	}
	h.idle = time.AfterFunc(idleShutdown, h.retire)
	return h, nil
}

func (h *host) format(ctx context.Context, spec Spec, path, text string) (string, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.dead {
		return "", errors.New("the formatter host stopped")
	}
	h.idle.Reset(idleShutdown)
	overrides := make([]string, 0, len(spec.Overrides))
	for key, value := range spec.Overrides {
		overrides = append(overrides, key+"="+value)
	}
	type result struct {
		status int
		value  string
		err    error
	}
	done := make(chan result, 1)
	go func() {
		for _, field := range []string{path, spec.EditorConfig, strings.Join(overrides, "\n"), text} {
			if err := writeField(h.stdin, field); err != nil {
				done <- result{err: err}
				return
			}
		}
		status, value, err := readFrame(h.stdout)
		done <- result{status, value, err}
	}()
	select {
	case r := <-done:
		if r.err != nil {
			h.stop()
			return "", fmt.Errorf("formatter host: %w", r.err)
		}
		if r.status != 0 {
			return "", errors.New(r.value)
		}
		return r.value, nil
	case <-ctx.Done():
		// The protocol has no way to abandon a request; a host mid-request
		// is out of step and is replaced by the next request.
		h.stop()
		return "", ctx.Err()
	}
}

// retire stops a host nobody has used for idleShutdown.
func (h *host) retire() {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.stop()
}

// stop ends the JVM. Called with h.mu held.
func (h *host) stop() {
	if h.dead {
		return
	}
	h.dead = true
	if h.idle != nil {
		h.idle.Stop()
	}
	_ = h.stdin.Close()
	if h.command.Process != nil {
		_ = h.command.Process.Kill()
	}
	_ = h.command.Wait()
	h.release()
	h.pool.mu.Lock()
	if h.pool.hosts[h.key] == h {
		delete(h.pool.hosts, h.key)
	}
	h.pool.mu.Unlock()
}

func writeField(w io.Writer, value string) error {
	var length [4]byte
	binary.BigEndian.PutUint32(length[:], uint32(len(value)))
	if _, err := w.Write(length[:]); err != nil {
		return err
	}
	_, err := io.WriteString(w, value)
	return err
}

func readFrame(r *bufio.Reader) (int, string, error) {
	var header [8]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return 0, "", err
	}
	status, length := int(binary.BigEndian.Uint32(header[:4])), binary.BigEndian.Uint32(header[4:])
	if length > 64<<20 {
		return 0, "", errors.New("oversized formatter response")
	}
	data := make([]byte, length)
	if _, err := io.ReadFull(r, data); err != nil {
		return 0, "", err
	}
	return status, string(data), nil
}

// buildHost compiles the host once per source version into the user cache.
// It uses only the JDK; the formatter is loaded reflectively at run time.
func buildHost(ctx context.Context, javaHome string) (string, error) {
	cache, err := os.UserCacheDir()
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256([]byte(hostSource))
	directory := filepath.Join(cache, "kotlsp", "formathost", hex.EncodeToString(digest[:])[:16])
	if fileExists(filepath.Join(directory, "KotlspFormatHost.class")) {
		return directory, nil
	}
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return "", err
	}
	javac := "javac"
	if javaHome != "" {
		if candidate := filepath.Join(javaHome, "bin", "javac"); fileExists(candidate) {
			javac = candidate
		}
	}
	staging, err := os.MkdirTemp(directory, "build-")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(staging)
	source := filepath.Join(staging, "KotlspFormatHost.java")
	if err := os.WriteFile(source, []byte(hostSource), 0o600); err != nil {
		return "", err
	}
	output, err := exec.CommandContext(ctx, javac, "-d", staging, source).CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("building the formatter host: %w: %s", err, strings.TrimSpace(string(output)))
	}
	// Published by rename, so a concurrent build never sees a partial class.
	if err := os.Rename(filepath.Join(staging, "KotlspFormatHost.class"), filepath.Join(directory, "KotlspFormatHost.class")); err != nil && !fileExists(filepath.Join(directory, "KotlspFormatHost.class")) {
		return "", err
	}
	return directory, nil
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.Mode().IsRegular()
}
