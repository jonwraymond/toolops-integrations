//go:build cgo

package bws

/*
// Bitwarden's vendored static library references libm symbols (e.g. pow).
// Ensure downstream binaries link with -lm in CGO builds (Linux CI, containers).
#cgo LDFLAGS: -lm
*/
import "C"

