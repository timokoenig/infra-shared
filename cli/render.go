package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"
	"unicode/utf8"
)

// Table prints aligned columns.
func Table(w io.Writer, header []string, rows [][]string) {
	tw := TabWriter(w)
	fmt.Fprintln(tw, strings.Join(header, "\t"))
	for _, r := range rows {
		fmt.Fprintln(tw, strings.Join(r, "\t"))
	}
	tw.Flush()
}

// TabWriter returns the tabwriter every tool uses.
func TabWriter(w io.Writer) *tabwriter.Writer {
	return tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
}

// PrintJSON writes v indented.
func PrintJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

// PrintJSON writes v indented to stdout.
func (c *Ctx) PrintJSON(v any) error { return PrintJSON(c.Stdout, v) }

// FmtTime renders a timestamp relative (2.5d ago) or absolute with --utc.
func (c *Ctx) FmtTime(t time.Time) string {
	if t.IsZero() {
		return "-"
	}
	if c.UTC {
		return t.UTC().Format("2006-01-02T15:04:05Z")
	}
	return FmtDur(c.Now().Sub(t)) + " ago"
}

// FmtDur renders a duration compactly: 12s, 5m, 3.5h, 2.1d.
func FmtDur(d time.Duration) string {
	switch {
	case d < 0:
		return "0s"
	case d < time.Minute:
		return strconv.Itoa(int(d.Seconds())) + "s"
	case d < time.Hour:
		return strconv.Itoa(int(d.Minutes())) + "m"
	case d < 48*time.Hour:
		return fmt.Sprintf("%.1fh", d.Hours())
	}
	return fmt.Sprintf("%.1fd", d.Hours()/24)
}

// Trunc shortens s to n runes, replacing newlines.
func Trunc(s string, n int) string {
	s = strings.ReplaceAll(strings.ReplaceAll(s, "\n", "⏎"), "\t", " ")
	if n <= 0 || utf8.RuneCountInString(s) <= n {
		return s
	}
	r := []rune(s)
	return string(r[:n-1]) + "…"
}

// Dash returns "-" for an empty string.
func Dash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// Join renders a list for a table cell.
func Join(ss []string) string {
	if len(ss) == 0 {
		return "-"
	}
	return strings.Join(ss, ",")
}
