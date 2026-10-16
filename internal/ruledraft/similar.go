package ruledraft

import (
	"math"
	"sort"
	"strings"
	"unicode"

	"github.com/jrsamsanchez/signalith/internal/detect"
)

// FindSimilar returns up to n library detections that look most like
// the description, best first. A word that few detections use, such as
// "kerberoasting", counts for more than one many use, such as "windows",
// and a word in the title for more than one in the description. When the
// description names attack behaviour (techniques, from its cues), sharing
// an ATT&CK technique counts for half the score.
func FindSimilar(description string, techniques []string, library []*detect.Detection, n int) []Similar {
	want := words(description)
	if len(want) == 0 || len(library) == 0 {
		return nil
	}
	cat := detect.ATTACK()
	type doc struct{ title, body map[string]bool }
	docs := make([]doc, len(library))
	df := map[string]int{}
	for i, d := range library {
		body := d.Description + " " + strings.Join(d.Tags, " ")
		for _, id := range d.MITRE {
			if t, ok := cat.Technique(id); ok {
				body += " " + t.Name
			}
		}
		docs[i] = doc{title: words(d.BaseTitle()), body: words(body)}
		for w := range want {
			if docs[i].title[w] || docs[i].body[w] {
				df[w]++
			}
		}
	}
	idf := map[string]float64{}
	var total float64
	for w := range want {
		idf[w] = math.Log(float64(len(library)+1) / float64(df[w]+1))
		total += idf[w]
	}
	if total == 0 {
		return nil
	}
	var out []Similar
	for i, d := range library {
		var got float64
		hits, inTitle := 0, 0
		for w := range want {
			switch {
			case docs[i].title[w]:
				got += idf[w]
				hits++
				inTitle++
			case docs[i].body[w]:
				got += 0.6 * idf[w]
				hits++
			}
		}
		tech := 0.0
		if len(techniques) > 0 {
			tech = techniqueMatch(techniques, d.MITRE)
		}
		if tech == 0 && (inTitle == 0 || hits < min(2, len(want))) {
			continue
		}
		score := got / total
		if len(techniques) > 0 {
			score = 0.5*score + 0.5*tech
		}
		if score < 0.35 {
			continue
		}
		out = append(out, Similar{ID: d.ID, Title: d.BaseTitle(), Severity: d.Severity, MITRE: d.MITRE, Enabled: d.Enabled, Source: d.Source, Score: math.Round(score*100) / 100})
	}
	sort.SliceStable(out, func(a, b int) bool {
		if out[a].Score != out[b].Score {
			return out[a].Score > out[b].Score
		}
		// Built-in detections are written for Signalith's own data.
		if (out[a].Source == "builtin") != (out[b].Source == "builtin") {
			return out[a].Source == "builtin"
		}
		return out[a].ID < out[b].ID
	})
	if len(out) > n {
		out = out[:n]
	}
	return out
}

// techniqueMatch is 1 when the detection has one of the techniques, 0.6
// when it has only a parent or sibling of one, else 0.
func techniqueMatch(want, have []string) float64 {
	best := 0.0
	parent := func(id string) string { p, _, _ := strings.Cut(id, "."); return p }
	for _, w := range want {
		for _, h := range have {
			switch {
			case strings.EqualFold(w, h):
				return 1
			case strings.EqualFold(parent(w), parent(h)):
				best = 0.6
			}
		}
	}
	return best
}

// ignored are words that say nothing about what to detect.
var ignored = map[string]bool{}

func init() {
	for _, w := range strings.Fields(`a an the of in on at for to from by and or with that when whenever if is are was were be been being any all
		some this these those it its as into than more less over under within each per same single one two three many much few
		alert alerts detect detection detections notify me us tell warn find show flag catch rule rules look watch someone something
		anyone anything event events happen happens happened time times minute minutes hour hours day days week weeks
		last past new recent get gets got do does did not no has have had there their they them can could should would will
		i we you he she his her my our your also just only about after before while during inside`) {
		ignored[w] = true
	}
}

// synonyms reduce words with the same meaning in detections to one.
var synonyms = map[string]string{
	"login": "logon", "logins": "logon", "logon": "logon", "logons": "logon", "signin": "logon", "signins": "logon", "logging": "logon", "logged": "logon", "signing": "logon", "signed": "logon",
	"log-in": "logon", "sign-in": "logon", "authentication": "logon", "authenticate": "logon",
	"failed": "fail", "failure": "fail", "failures": "fail", "fails": "fail", "failing": "fail", "unsuccessful": "fail",
	"administrator": "admin", "administrators": "admin", "admins": "admin", "privileged": "admin",
	"host": "system", "hosts": "system", "machine": "system", "machines": "system", "computer": "system", "computers": "system", "server": "system", "servers": "system",
	"account": "user", "accounts": "user", "users": "user",
	"process": "process", "processes": "process", "program": "process", "programs": "process", "executable": "process",
	"deleted": "delete", "deletes": "delete", "deleting": "delete", "deletion": "delete", "removed": "delete", "remove": "delete",
	"created": "create", "creates": "create", "creating": "create", "creation": "create",
	"cleared": "clear", "clears": "clear", "clearing": "clear",
	"disabled": "disable", "disables": "disable", "disabling": "disable",
	"powershell": "powershell", "pwsh": "powershell",
	"encoded": "encode", "encoding": "encode", "base64": "encode",
	"dumping": "dump", "dumped": "dump", "dumps": "dump",
	"scanning": "scan", "scans": "scan", "scanned": "scan", "scanner": "scan",
	"brute": "brute", "bruteforce": "brute", "guessing": "brute",
	"spraying": "spray", "sprayed": "spray",
}

// words splits text into its meaningful words, folded to a common form.
func words(text string) map[string]bool {
	out := map[string]bool{}
	for _, w := range strings.FieldsFunc(strings.ToLower(text), func(r rune) bool {
		return !unicode.IsLetter(r) && !unicode.IsDigit(r) && r != '-'
	}) {
		w = strings.Trim(w, "-")
		if len(w) < 2 || ignored[w] {
			continue
		}
		if s, ok := synonyms[w]; ok {
			w = s
		} else {
			w = stem(w)
		}
		if !ignored[w] {
			out[w] = true
		}
	}
	return out
}

// stem drops common English endings so "tasks" matches "task".
func stem(w string) string {
	switch {
	case len(w) > 5 && strings.HasSuffix(w, "ing"):
		return w[:len(w)-3]
	case len(w) > 4 && strings.HasSuffix(w, "ies"):
		return w[:len(w)-3] + "y"
	case len(w) > 4 && strings.HasSuffix(w, "ed"):
		return w[:len(w)-2]
	case len(w) > 3 && strings.HasSuffix(w, "s") && !strings.HasSuffix(w, "ss"):
		return w[:len(w)-1]
	}
	return w
}
