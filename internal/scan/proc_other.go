//go:build !windows

package scan

import "os/exec"

// hidden ist ausserhalb von Windows ein Durchreicher: Es gibt dort kein
// Konsolenfenster, das aufblitzen koennte (siehe proc_windows.go).
func hidden(cmd *exec.Cmd) *exec.Cmd { return cmd }
