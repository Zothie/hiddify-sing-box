package adaptive

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

const maxHintBytes = 16384

type winnerHint struct {
	Version  int    `json:"version"`
	Key      string `json:"key"`
	LastGood string `json:"last_good"`
}

func (c *Coordinator) stateError(err error) {
	if err != nil {
		c.state.StateError = fmt.Sprintf("adaptive state: %v", err)
	}
}

func (c *Coordinator) loadHint() {
	if !c.persistenceEnabled || c.cfg.StatePath == "" {
		return
	}
	entry, err := os.Lstat(c.cfg.StatePath)
	if errors.Is(err, os.ErrNotExist) {
		return
	}
	if err != nil {
		c.stateError(err)
		return
	}
	if !entry.Mode().IsRegular() {
		c.stateError(errors.New("hint is not a regular file"))
		return
	}
	f, err := os.Open(c.cfg.StatePath)
	if errors.Is(err, os.ErrNotExist) {
		return
	}
	if err != nil {
		c.stateError(err)
		return
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		c.stateError(err)
		return
	}
	if !info.Mode().IsRegular() {
		c.stateError(errors.New("hint is not a regular file"))
		return
	}
	b, err := io.ReadAll(io.LimitReader(f, maxHintBytes+1))
	if err != nil {
		c.stateError(err)
		return
	}
	if len(b) > maxHintBytes {
		c.stateError(errors.New("hint exceeds size limit"))
		return
	}
	var h winnerHint
	if err = json.Unmarshal(b, &h); err != nil {
		c.stateError(err)
		return
	}
	if h.Version != 1 {
		c.stateError(errors.New("unsupported hint version"))
		return
	}
	if h.Key != c.cfg.StateKey {
		return
	}
	if indexOfCandidate(c.cfg.Candidates, h.LastGood) < 0 {
		c.stateError(errors.New("unknown hint candidate"))
		return
	}
	c.state.LastGood = h.LastGood
	c.state.StateLoaded = true
}

func syncParent(path string) error {
	d, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

// Serialized with promotion and ResetNetwork under mu. State is only a hint;
// no persisted bytes can manufacture a candidate or a verified connection.
func (c *Coordinator) saveHint() {
	c.state.StateSaved = false
	if !c.persistenceEnabled || c.cfg.StatePath == "" {
		return
	}
	err := c.writeHint()
	c.stateError(err)
	c.state.StateSaved = err == nil
}
func (c *Coordinator) writeHint() error {
	b, err := json.Marshal(winnerHint{1, c.cfg.StateKey, c.state.LastGood})
	if err != nil {
		return err
	}
	if len(b) > maxHintBytes {
		return errors.New("hint exceeds size limit")
	}
	f, err := os.CreateTemp(filepath.Dir(c.cfg.StatePath), ".hydra-winner-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	defer f.Close()
	if err = f.Chmod(0600); err != nil {
		return err
	}
	if _, err = f.Write(b); err != nil {
		return err
	}
	if err = f.Sync(); err != nil {
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	if err = os.Rename(f.Name(), c.cfg.StatePath); err != nil {
		return err
	}
	return syncParent(c.cfg.StatePath)
}
func (c *Coordinator) clearHint() {
	c.state.StateSaved = false
	if c.cfg.StatePath == "" {
		return
	}
	err := os.Remove(c.cfg.StatePath)
	if errors.Is(err, os.ErrNotExist) {
		return
	}
	if err == nil {
		err = syncParent(c.cfg.StatePath)
	}
	c.stateError(err)
}
