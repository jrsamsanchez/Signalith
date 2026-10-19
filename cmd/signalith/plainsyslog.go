package main

import (
	"log/slog"
	"time"

	"github.com/jrsamsanchez/signalith/internal/config"
)

// decidePlainSyslog makes, on the first start of the Docker quick start
// with this version, the decision whether it keeps the plain syslog its
// older signalith.yaml had (config.DecidePlainSyslog), logs it, and
// returns the config loaded again when it was made now. Elsewhere it
// returns c as it is.
func decidePlainSyslog(path string, c *config.Config, log *slog.Logger) (*config.Config, error) {
	p, now, err := config.DecidePlainSyslog(c, time.Now())
	if err != nil {
		// Decided again at the next start; until then nothing changes.
		log.Error("could not keep the decision about plain syslog in the state folder", "file", config.PlainSyslogFileIn(c.StateDir()), "err", err)
		return c, nil
	}
	if !now {
		return c, nil
	}
	if p.Kept {
		log.Warn("this Docker quick start was there before syslog over TLS became the only default, so it keeps receiving plain syslog over UDP and TCP on "+
			config.QuickStartPlainAddr+" (port 514 on this computer). Plain syslog is unencrypted and can be forged: turn it off on the Settings page (Syslog) once every device sends over TLS",
			"file", config.PlainSyslogFileIn(c.StateDir()))
	} else {
		log.Info("this Docker quick start started new, so it takes syslog over TLS only; Add data > Syslog turns on plain syslog", "file", config.PlainSyslogFileIn(c.StateDir()))
	}
	return loadConfig(path, log)
}
