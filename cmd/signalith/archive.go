package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/jrsamsanchez/signalith/internal/config"
	"github.com/jrsamsanchez/signalith/internal/ingest"
	"github.com/jrsamsanchez/signalith/internal/retention"
	"github.com/jrsamsanchez/signalith/internal/store"
)

const archiveUsage = `Usage:
  signalith archive list    [-c file] [-dir folder]
  signalith archive verify  [-c file] [-dir folder] <file or id>...
  signalith archive restore [-c file] [-dir folder] [-keep-days N] <file or id>...

An archived day is a <index>.ndjson.gz file with a <index>.json manifest
beside it. Name it by its file path or, for files in the archive folder,
by its ID (the file name without .ndjson.gz). The archive folder is
retention.archive_dir, SIGNALITH_ARCHIVE_DIR, or an "archive" folder next
to lookups.dir; -dir overrides it. Installs that set SIGNALITH_ARCHIVE_DIR
for the service (the systemd unit sets /var/lib/signalith/archive) need
the same here, or -dir.

restore installs Signalith's index template first, so restored days get
the same field types as live ones, even on a new OpenSearch.`

func cmdArchive(args []string) error {
	if len(args) == 0 {
		return errors.New(archiveUsage)
	}
	sub := args[0]
	fs := flag.NewFlagSet("archive "+sub, flag.ExitOnError)
	fs.Usage = func() { fmt.Fprintln(os.Stderr, archiveUsage) }
	path := configFlag(fs)
	dir := fs.String("dir", "", "archive folder (default: from the config file)")
	keep := fs.Int("keep-days", retention.DefaultRestoreDays, "days a restored day stays searchable before retention may delete it again")
	fs.Parse(args[1:])
	c, err := config.Load(*path)
	if err != nil {
		return err
	}
	folder := c.ArchiveDir()
	if *dir != "" {
		folder = *dir
	}
	switch sub {
	case "list":
		return archiveList(folder)
	case "verify":
		return archiveEach(folder, fs.Args(), func(a *retention.Archive, m retention.Manifest) error {
			if err := a.Verify(m); err != nil {
				return err
			}
			fmt.Printf("%s: OK, %d events, sha256 %s\n", m.File, m.Docs, m.SHA256)
			return nil
		})
	case "restore":
		if *keep < 1 || *keep > retention.MaxRestoreDays {
			return fmt.Errorf("-keep-days must be between 1 and %d", retention.MaxRestoreDays)
		}
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
		defer stop()
		cl := newStore(c)
		hctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		_, herr := cl.Health(hctx)
		if herr == nil {
			// Without the template, OpenSearch would guess field types (text
			// instead of keyword), and searches and stats on these days
			// would not work like on others. Starting the server later does
			// not fix indices that already exist.
			herr = ingest.PutIndexTemplate(hctx, cl, c.OpenSearch.IndexPrefix, c.OpenSearch.Replicas)
			if herr != nil {
				herr = fmt.Errorf("could not install the index template, so nothing was restored: %w", herr)
			}
		} else {
			herr = errors.New(store.Unusable(herr))
		}
		cancel()
		if herr != nil {
			return herr
		}
		until := time.Now().UTC().AddDate(0, 0, *keep).Format(time.DateOnly)
		return archiveEach(folder, fs.Args(), func(a *retention.Archive, m retention.Manifest) error {
			if cat, _, ok := retention.ParseIndex(c.OpenSearch.IndexPrefix, m.Index); !ok || cat != m.Category {
				return fmt.Errorf("it was archived from %s, which is not a %s-* daily index", m.Index, c.OpenSearch.IndexPrefix)
			}
			mgr := &retention.Manager{Cluster: retention.NewOpenSearch(cl), Prefix: c.OpenSearch.IndexPrefix, Archive: a}
			fmt.Printf("Restoring %s (%d events) into %s...\n", m.File, m.Docs, m.Index)
			last := time.Now()
			n, err := mgr.RestoreArchive(ctx, m, until, func(done int64) {
				if time.Since(last) > 5*time.Second {
					fmt.Printf("  %d of %d events\n", done, m.Docs)
					last = time.Now()
				}
			})
			if err != nil {
				return err
			}
			fmt.Printf("Restored %d events into %s; it stays searchable until %s.\n", n, m.Index, until)
			return nil
		})
	default:
		return fmt.Errorf("unknown archive command %q\n\n%s", sub, archiveUsage)
	}
}

func archiveList(folder string) error {
	a := &retention.Archive{Dir: folder}
	list, problems, err := a.List()
	if err != nil {
		return err
	}
	fmt.Printf("Archive folder: %s\n\n", folder)
	if _, err := os.Stat(folder); errors.Is(err, os.ErrNotExist) {
		fmt.Println("That folder does not exist yet. If the server archives elsewhere (systemd installs")
		fmt.Println("use /var/lib/signalith/archive), name that folder with -dir, or set")
		fmt.Println("SIGNALITH_ARCHIVE_DIR as the server does.")
		return nil
	}
	if len(list) == 0 {
		fmt.Println("No archived days.")
	} else {
		tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
		fmt.Fprintln(tw, "DAY\tCATEGORY\tEVENTS\tSIZE\tID")
		var total int64
		for _, m := range list {
			name := m.Category
			if c, ok := retention.CategoryByID(m.Category); ok {
				name = c.Name
			}
			fmt.Fprintf(tw, "%s\t%s\t%d\t%s\t%s\n", m.Day, name, m.Docs, humanBytes(m.Bytes), m.ID)
			total += m.Bytes
		}
		tw.Flush()
		fmt.Printf("\n%d archived days, %s.\n", len(list), humanBytes(total))
	}
	for _, p := range problems {
		fmt.Println("Problem:", p)
	}
	return nil
}

// archiveEach runs fn for each named archive, reporting every failure.
func archiveEach(folder string, names []string, fn func(*retention.Archive, retention.Manifest) error) error {
	if len(names) == 0 {
		return errors.New("name at least one archive file or ID; list them with: signalith archive list")
	}
	failed := 0
	for _, name := range names {
		a, id := &retention.Archive{Dir: folder}, name
		if strings.ContainsAny(name, `/\`) || strings.HasSuffix(name, ".ndjson.gz") || strings.HasSuffix(name, ".json") {
			a.Dir = filepath.Dir(name)
			id = strings.TrimSuffix(strings.TrimSuffix(filepath.Base(name), ".ndjson.gz"), ".json")
		}
		m, err := a.Get(id)
		if err == nil {
			err = fn(a, m)
		}
		if err != nil {
			failed++
			fmt.Fprintf(os.Stderr, "%s: %v\n", name, err)
		}
	}
	if failed > 0 {
		return fmt.Errorf("%d of %d failed", failed, len(names))
	}
	return nil
}

func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(n)/float64(div), "KMGTPE"[exp])
}
