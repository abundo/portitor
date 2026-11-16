// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package confview

import (
	"database/sql"
	"database/sql/driver"
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"time"
)

// The models' columns, read from their fields: a field's column is its tag's
// `gorm:"column:..."` or its name in snake case (as the rows were named when
// they were tables, so the tags stay as they are), an embedded struct's
// fields are the model's, `gorm:"-"` and relations (a struct or a list of
// structs that is no column type) have none, and `gorm:"default:..."` is the
// value a zero field takes in a row.

// field is a model's field that is a column.
type field struct {
	column string
	index  []int // reflect's, through embedded structs
	typ    reflect.Type
	def    string // the default, "" for none
	hasDef bool
}

// modelInfo is a model's columns.
type modelInfo struct {
	fields   []field
	byColumn map[string]*field
}

var modelCache sync.Map // reflect.Type -> *modelInfo

// infoOf is the columns of the struct type t.
func infoOf(t reflect.Type) *modelInfo {
	if v, ok := modelCache.Load(t); ok {
		return v.(*modelInfo)
	}
	m := &modelInfo{byColumn: map[string]*field{}}
	var walk func(t reflect.Type, index []int)
	walk = func(t reflect.Type, index []int) {
		for i := range t.NumField() {
			sf := t.Field(i)
			idx := append(append([]int(nil), index...), i)
			tags := gormTags(sf.Tag.Get("gorm"))
			if _, skip := tags["-"]; skip {
				continue
			}
			if sf.Anonymous && sf.Type.Kind() == reflect.Struct {
				walk(sf.Type, idx)
				continue
			}
			if !sf.IsExported() || isRelation(sf.Type) {
				continue
			}
			f := field{column: tags["column"], index: idx, typ: sf.Type}
			if f.column == "" {
				f.column = snakeCase(sf.Name)
			}
			f.def, f.hasDef = tags["default"]
			m.fields = append(m.fields, f)
		}
	}
	walk(t, nil)
	for i := range m.fields {
		m.byColumn[m.fields[i].column] = &m.fields[i]
	}
	v, _ := modelCache.LoadOrStore(t, m)
	return v.(*modelInfo)
}

// gormTags are a gorm tag's settings: "column:x;default:y;-".
func gormTags(tag string) map[string]string {
	out := map[string]string{}
	for _, part := range strings.Split(tag, ";") {
		if part = strings.TrimSpace(part); part == "" {
			continue
		}
		k, v, _ := strings.Cut(part, ":")
		out[strings.TrimSpace(k)] = strings.TrimSpace(v)
	}
	return out
}

var (
	scannerType = reflect.TypeFor[sql.Scanner]()
	valuerType  = reflect.TypeFor[driver.Valuer]()
	timeType    = reflect.TypeFor[time.Time]()
)

// isColumnType reports whether a field of type t holds a column's value
// itself: what scans or gives a value does, a struct or a list of structs
// otherwise not.
func isColumnType(t reflect.Type) bool {
	return t.Implements(valuerType) || reflect.PointerTo(t).Implements(scannerType)
}

// isRelation reports whether a field of type t is no column: a struct (but a
// time or a column type) or a list of structs.
func isRelation(t reflect.Type) bool {
	if isColumnType(t) {
		return false
	}
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	switch t.Kind() {
	case reflect.Struct:
		return t != timeType
	case reflect.Slice, reflect.Array:
		e := t.Elem()
		for e.Kind() == reflect.Pointer {
			e = e.Elem()
		}
		return e.Kind() == reflect.Struct && !isColumnType(t)
	case reflect.Map, reflect.Interface, reflect.Func, reflect.Chan:
		return true
	}
	return false
}

// initialisms are written in one piece in a column's name (ID: id, not i_d).
var initialisms = func() *strings.Replacer {
	var pairs []string
	for _, w := range []string{"API", "ASCII", "CPU", "CSS", "DNS", "EOF", "GUID", "HTML", "HTTP", "HTTPS", "ID", "IP", "JSON", "LHS", "QPS", "RAM", "RHS", "RPC", "SLA", "SMTP", "SSH", "TLS", "TTL", "UID", "UI", "UUID", "URI", "URL", "UTF8", "VM", "XML", "XSRF", "XSS"} {
		pairs = append(pairs, w, w[:1]+strings.ToLower(w[1:]))
	}
	return strings.NewReplacer(pairs...)
}()

// snakeCase is a field's name as its column: AgentURL is agent_url,
// IPv6Prefix ip_v6_prefix (the naming the tables had).
func snakeCase(name string) string {
	if name == "" {
		return ""
	}
	value := initialisms.Replace(name)
	isUpper := func(c byte) bool { return c >= 'A' && c <= 'Z' }
	var buf strings.Builder
	lastCase, curCase := false, isUpper(value[0])
	for i := 0; i < len(value)-1; i++ {
		c := value[i]
		nextCase := isUpper(value[i+1])
		nextNumber := value[i+1] >= '0' && value[i+1] <= '9'
		if curCase {
			if !(lastCase && (nextCase || nextNumber)) && i > 0 && value[i-1] != '_' && value[i+1] != '_' {
				buf.WriteByte('_')
			}
			buf.WriteByte(c + 32)
		} else {
			buf.WriteByte(c)
		}
		lastCase, curCase = curCase, nextCase
	}
	last := value[len(value)-1]
	if curCase {
		if !lastCase && len(value) > 1 {
			buf.WriteByte('_')
		}
		buf.WriteByte(last + 32)
	} else {
		buf.WriteByte(last)
	}
	return buf.String()
}

// setField sets the field fv to a column's value: int64, float64, bool,
// string, []byte, time.Time or nil, converted as the field needs.
func setField(fv reflect.Value, val any) error {
	if val == nil {
		fv.SetZero()
		return nil
	}
	if fv.Kind() == reflect.Pointer && !fv.Type().Implements(scannerType) {
		p := reflect.New(fv.Type().Elem())
		if err := setField(p.Elem(), val); err != nil {
			return err
		}
		fv.Set(p)
		return nil
	}
	if sc, ok := fv.Addr().Interface().(sql.Scanner); ok {
		return sc.Scan(val)
	}
	rv := reflect.ValueOf(val)
	if rv.Type().AssignableTo(fv.Type()) {
		fv.Set(rv)
		return nil
	}
	switch fv.Kind() {
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		n, err := toInt64(val)
		if err != nil {
			return err
		}
		fv.SetInt(n)
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		n, err := toInt64(val)
		if err != nil {
			return err
		}
		fv.SetUint(uint64(n))
	case reflect.Float32, reflect.Float64:
		switch v := val.(type) {
		case float64:
			fv.SetFloat(v)
		case int64:
			fv.SetFloat(float64(v))
		case string:
			f, err := strconv.ParseFloat(v, 64)
			if err != nil {
				return err
			}
			fv.SetFloat(f)
		default:
			return fmt.Errorf("can't set a number from %T", val)
		}
	case reflect.Bool:
		switch v := val.(type) {
		case bool:
			fv.SetBool(v)
		case int64:
			fv.SetBool(v != 0)
		case string:
			b, err := strconv.ParseBool(v)
			if err != nil {
				return err
			}
			fv.SetBool(b)
		default:
			return fmt.Errorf("can't set a boolean from %T", val)
		}
	case reflect.String:
		switch v := val.(type) {
		case string:
			fv.SetString(v)
		case []byte:
			fv.SetString(string(v))
		case int64:
			fv.SetString(strconv.FormatInt(v, 10))
		case float64:
			fv.SetString(strconv.FormatFloat(v, 'f', -1, 64))
		case bool:
			fv.SetString(strconv.FormatBool(v))
		default:
			return fmt.Errorf("can't set a string from %T", val)
		}
	case reflect.Slice:
		if fv.Type().Elem().Kind() == reflect.Uint8 {
			if s, ok := val.(string); ok {
				fv.SetBytes([]byte(s))
				return nil
			}
		}
		return fmt.Errorf("can't set %s from %T", fv.Type(), val)
	case reflect.Struct:
		if fv.Type() == timeType {
			if s, ok := val.(string); ok {
				t, err := time.Parse(time.RFC3339Nano, s)
				if err != nil {
					return err
				}
				fv.Set(reflect.ValueOf(t))
				return nil
			}
		}
		return fmt.Errorf("can't set %s from %T", fv.Type(), val)
	default:
		return fmt.Errorf("can't set %s from %T", fv.Type(), val)
	}
	return nil
}

func toInt64(val any) (int64, error) {
	switch v := val.(type) {
	case int64:
		return v, nil
	case float64:
		return int64(v), nil
	case bool:
		if v {
			return 1, nil
		}
		return 0, nil
	case string:
		return strconv.ParseInt(v, 10, 64)
	}
	return 0, fmt.Errorf("can't set a number from %T", val)
}

// defaultValue is the column's value of a field's default (gorm:"default:").
func defaultValue(f *field) (any, error) {
	t := f.typ
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	v := reflect.New(t).Elem()
	def := strings.Trim(f.def, "'")
	if err := setField(v, def); err != nil {
		return nil, fmt.Errorf("%s's default %q: %w", f.column, f.def, err)
	}
	return plainValue(v), nil
}
