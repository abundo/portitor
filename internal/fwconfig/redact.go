// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package fwconfig

import (
	"reflect"
)

// Redacted is the placeholder of a secret in a redacted document.
const Redacted = "<redacted>"

// Redacted is a deep copy of d with its secrets masked, for the deployment
// history: the fields tagged `secret:"true"` (a string, masked when set),
// and `secret:"provider"` (a DNS provider's settings, the secret ones and
// any the provider named in the struct's Provider doesn't know).
// TestSecretsTagged fails on a field that looks secret and has no tag.
func (d Document) Redacted() Document {
	return redactCopy(reflect.ValueOf(d)).Interface().(Document)
}

// redactCopy is a deep copy of v with the tagged fields of its structs
// masked.
func redactCopy(v reflect.Value) reflect.Value {
	switch v.Kind() {
	case reflect.Pointer:
		if v.IsNil() {
			return v
		}
		out := reflect.New(v.Type().Elem())
		out.Elem().Set(redactCopy(v.Elem()))
		return out
	case reflect.Slice:
		if v.IsNil() {
			return v
		}
		out := reflect.MakeSlice(v.Type(), v.Len(), v.Len())
		for i := range v.Len() {
			out.Index(i).Set(redactCopy(v.Index(i)))
		}
		return out
	case reflect.Map:
		if v.IsNil() {
			return v
		}
		out := reflect.MakeMapWithSize(v.Type(), v.Len())
		for it := v.MapRange(); it.Next(); {
			out.SetMapIndex(it.Key(), redactCopy(it.Value()))
		}
		return out
	case reflect.Struct:
		out := reflect.New(v.Type()).Elem()
		out.Set(v) // the unexported fields, shallow
		t := v.Type()
		for i := range t.NumField() {
			f := t.Field(i)
			if !f.IsExported() {
				continue
			}
			fv := out.Field(i)
			fv.Set(redactCopy(v.Field(i)))
			switch f.Tag.Get("secret") {
			case "true":
				if fv.Kind() == reflect.String && fv.String() != "" {
					fv.SetString(Redacted)
				}
			case "provider":
				settings, _ := fv.Interface().(map[string]string)
				fv.Set(reflect.ValueOf(redactProviderSettings(out.FieldByName("Provider").String(), settings)))
			}
		}
		return out
	}
	return v
}

// redactProviderSettings masks a DNS provider's secret settings, and any
// it doesn't know (all of them, of a provider it doesn't know).
func redactProviderSettings(provider string, settings map[string]string) map[string]string {
	if len(settings) == 0 {
		return settings
	}
	p := FindDNSProvider(provider)
	out := make(map[string]string, len(settings))
	for k, v := range settings {
		if p == nil {
			v = Redacted
		} else if f := p.Field(k); f == nil || f.Secret {
			v = Redacted
		}
		out[k] = v
	}
	return out
}
