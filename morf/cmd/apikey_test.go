/*
Copyright [2023] [Amrudesh Balakrishnan]

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package cmd

import "testing"

func TestParseScopes(t *testing.T) {
	cases := []struct {
		in   string
		want []string
	}{
		{"", []string{}},
		{"scan:write", []string{"scan:write"}},
		{"a, b ,c", []string{"a", "b", "c"}},
		{" , ,", []string{}},
		{"*", []string{"*"}},
	}
	for _, c := range cases {
		got := parseScopes(c.in)
		if len(got) != len(c.want) {
			t.Errorf("parseScopes(%q) = %v (len %d), want %v", c.in, got, len(got), c.want)
			continue
		}
		for i := range got {
			if got[i] != c.want[i] {
				t.Errorf("parseScopes(%q)[%d] = %q, want %q", c.in, i, got[i], c.want[i])
			}
		}
	}
}
