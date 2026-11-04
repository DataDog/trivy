package strings

import (
	"fmt"
	"strings"

	xslices "github.com/aquasecurity/trivy/pkg/x/slices"
)

type String interface {
	~string
}

func ToStringSlice[T any](ss []T) []string {
	if len(ss) == 0 {
		return nil
	}
	return xslices.Map(ss, func(s T) string {
		switch v := any(s).(type) {
		case string:
			return v
		case fmt.Stringer:
			return v.String()
		default:
			if stringer, ok := any(&s).(fmt.Stringer); ok {
				return stringer.String()
			}
			return fmt.Sprint(v)
		}
	})
}

func ToTSlice[T String](ss []string) []T {
	if ss == nil {
		return nil
	}
	return xslices.Map(ss, func(s string) T {
		return T(s)
	})
}

// CutLast slices s around the last instance of sep,
// returning the text before and after sep.
// The found result reports whether sep appears in s.
// If sep does not appear in s, CutLast returns s, "", false.
//
// CutLast is strings.CutLast from Go 1.27.
func CutLast(s, sep string) (before, after string, found bool) {
	if i := strings.LastIndex(s, sep); i >= 0 {
		return s[:i], s[i+len(sep):], true
	}
	return s, "", false
}
