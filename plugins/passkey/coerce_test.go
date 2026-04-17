package passkey

import "testing"

func TestCoerceUint32(t *testing.T) {
	cases := []struct {
		name string
		in   any
		want uint32
	}{
		{"int (memory adapter)", int(42), 42},
		{"int64 (sqlx adapter)", int64(42), 42},
		{"int32", int32(42), 42},
		{"uint32", uint32(42), 42},
		{"uint64", uint64(42), 42},
		{"float64 (JSON round-trip)", float64(42), 42},
		{"nil", nil, 0},
		{"string (unsupported)", "42", 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := coerceUint32(tc.in); got != tc.want {
				t.Errorf("coerceUint32(%v) = %d, want %d", tc.in, got, tc.want)
			}
		})
	}
}
