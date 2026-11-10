// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package fwconfig

import (
	"reflect"
	"regexp"
	"testing"
)

// secretName is a field name that looks like it holds a secret.
var secretName = regexp.MustCompile(`(?i)secret|passw|privkey|private|preshared|apikey|authkey|updatekey|tlscrypt|totp|community|token|hash|^key$`)

// notSecret are fields that match secretName and hold no secret, by
// "Type.Field".
var notSecret = map[string]bool{
	"DNSProviderField.Key":            true, // a setting's name
	"DNSProviderField.Secret":         true, // whether the setting is secret
	"ISIS.AreaPasswordType":           true, // clear or md5
	"ISIS.DomainPasswordType":         true,
	"ISISInterface.PasswordType":      true,
	"RouteMapEntry.MatchCommunity":    true, // BGP communities
	"RouteMapEntry.SetCommunity":      true,
	"RouteMapEntry.SetLargeCommunity": true,
}

// TestSecretsTagged: every string (or map) of the document that looks
// secret is tagged for Redacted (or listed in notSecret).
func TestSecretsTagged(t *testing.T) {
	seen := map[reflect.Type]bool{}
	var walk func(reflect.Type)
	walk = func(typ reflect.Type) {
		switch typ.Kind() {
		case reflect.Pointer, reflect.Slice, reflect.Array, reflect.Map:
			walk(typ.Elem())
			return
		case reflect.Struct:
		default:
			return
		}
		if seen[typ] {
			return
		}
		seen[typ] = true
		for i := range typ.NumField() {
			f := typ.Field(i)
			if !f.IsExported() {
				continue
			}
			walk(f.Type)
			name := typ.Name() + "." + f.Name
			text := f.Type.Kind() == reflect.String || f.Type.Kind() == reflect.Map
			if text && f.Tag.Get("secret") == "" && secretName.MatchString(f.Name) && !notSecret[name] {
				t.Errorf("%s looks secret: tag it `secret:\"true\"` or list it in notSecret", name)
			}
		}
	}
	walk(reflect.TypeFor[Document]())
}

// TestRedacted: every tagged field is masked in the copy and kept in the
// original.
func TestRedacted(t *testing.T) {
	var doc Document
	fill(reflect.ValueOf(&doc).Elem())
	red := doc.Redacted()
	check(t, "Document", reflect.ValueOf(doc), reflect.ValueOf(red))
}

// fill sets every string to "x", every map to one entry and every slice
// and pointer to one element, all the way down.
func fill(v reflect.Value) {
	switch v.Kind() {
	case reflect.String:
		v.SetString("x")
	case reflect.Pointer:
		if v.IsNil() {
			v.Set(reflect.New(v.Type().Elem()))
			fill(v.Elem())
		}
	case reflect.Slice:
		v.Set(reflect.MakeSlice(v.Type(), 1, 1))
		fill(v.Index(0))
	case reflect.Map:
		m := reflect.MakeMap(v.Type())
		k, e := reflect.New(v.Type().Key()).Elem(), reflect.New(v.Type().Elem()).Elem()
		fill(k)
		fill(e)
		m.SetMapIndex(k, e)
		v.Set(m)
	case reflect.Struct:
		for i := range v.NumField() {
			if v.Type().Field(i).IsExported() {
				fill(v.Field(i))
			}
		}
	}
}

func check(t *testing.T, at string, orig, red reflect.Value) {
	switch orig.Kind() {
	case reflect.Pointer:
		if !orig.IsNil() {
			if orig.Pointer() == red.Pointer() {
				t.Errorf("%s: shared with the original", at)
			}
			check(t, at, orig.Elem(), red.Elem())
		}
	case reflect.Slice:
		for i := range orig.Len() {
			check(t, at+"[]", orig.Index(i), red.Index(i))
		}
	case reflect.Struct:
		typ := orig.Type()
		for i := range typ.NumField() {
			f := typ.Field(i)
			if !f.IsExported() {
				continue
			}
			name := at + "." + f.Name
			switch f.Tag.Get("secret") {
			case "true":
				if orig.Field(i).String() != "x" || red.Field(i).String() != Redacted {
					t.Errorf("%s: %q in the original, %q redacted", name, orig.Field(i).String(), red.Field(i).String())
				}
			case "provider":
				// Provider "x" is unknown: every setting is masked.
				for it := red.Field(i).MapRange(); it.Next(); {
					if it.Value().String() != Redacted {
						t.Errorf("%s[%s] = %q", name, it.Key(), it.Value())
					}
				}
				if orig.Field(i).MapIndex(reflect.ValueOf("x")).String() != "x" {
					t.Errorf("%s: original changed", name)
				}
			default:
				check(t, name, orig.Field(i), red.Field(i))
			}
		}
	}
}
