//go:build !windows

package main

import "fmt"

func platformProductMode(gui, service bool, activation string) bool {
	if gui || service {
		fmt.Println("Product GUI and broker are Windows-only; use classic CLI on this OS.")
		return true
	}
	return false
}
