package audit

import (
	"fmt"
	"os"
	"regexp"
	"sort"
	"strconv"
	"time"
)

// File names are audit-YYYY-MM-DD.jsonl for the first file of a UTC day and
// audit-YYYY-MM-DD.N.jsonl (N >= 1) for the files that follow it when the
// size limit is reached. Lexical order of the date plus numeric order of N is
// chronological order.
var fileRE = regexp.MustCompile(`^audit-(\d{4}-\d{2}-\d{2})(?:\.(\d+))?\.jsonl$`)

const dateLayout = "2006-01-02"

type fileName struct {
	Name string
	Date string // YYYY-MM-DD
	Seq  int
}

func (f fileName) day() (time.Time, bool) {
	t, err := time.Parse(dateLayout, f.Date)
	return t, err == nil
}

func nameOf(date string, seq int) string {
	if seq == 0 {
		return fmt.Sprintf("audit-%s.jsonl", date)
	}
	return fmt.Sprintf("audit-%s.%d.jsonl", date, seq)
}

// listFiles returns the audit files in dir, oldest first. A missing directory
// is an empty list.
func listFiles(dir string) ([]fileName, error) {
	ents, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var out []fileName
	for _, e := range ents {
		if e.IsDir() {
			continue
		}
		m := fileRE.FindStringSubmatch(e.Name())
		if m == nil {
			continue
		}
		seq := 0
		if m[2] != "" {
			seq, _ = strconv.Atoi(m[2])
		}
		out = append(out, fileName{Name: e.Name(), Date: m[1], Seq: seq})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Date != out[j].Date {
			return out[i].Date < out[j].Date
		}
		return out[i].Seq < out[j].Seq
	})
	return out, nil
}
