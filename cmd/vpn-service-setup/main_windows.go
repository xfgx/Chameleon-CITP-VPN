//go:build windows

// Installer-only SCM helper. No tunnel, network or arbitrary service operations.
package main

import (
	"errors"
	"flag"
	"fmt"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

const serviceName = "ChameleonBroker"

func wait(s *mgr.Service, target svc.State) error {
	deadline := time.Now().Add(40 * time.Second)
	for time.Now().Before(deadline) {
		st, e := s.Query()
		if e != nil {
			return e
		}
		if st.State == target {
			return nil
		}
		if target == svc.Running && st.State == svc.Stopped {
			return fmt.Errorf("service stopped: Windows=%d, service=%d", st.Win32ExitCode, st.ServiceSpecificExitCode)
		}
		time.Sleep(200 * time.Millisecond)
	}
	return errors.New("service transition timed out; close Chameleon and retry")
}
func stop(s *mgr.Service) error {
	st, e := s.Query()
	if e != nil {
		return e
	}
	if st.State == svc.Stopped {
		return nil
	}
	if st.State != svc.StopPending {
		if _, e = s.Control(svc.Stop); e != nil && !errors.Is(e, windows.ERROR_SERVICE_NOT_ACTIVE) {
			return e
		}
	}
	return wait(s, svc.Stopped)
}
func protect(s *mgr.Service) error {
	sd, e := windows.SecurityDescriptorFromString("D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;CCLCSWLOCRRC;;;IU)")
	if e != nil {
		return e
	}
	dacl, _, e := sd.DACL()
	if e != nil {
		return e
	}
	return windows.SetSecurityInfo(s.Handle, windows.SE_SERVICE, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil)
}
func perform(action string) error {
	pf, e := windows.KnownFolderPath(windows.FOLDERID_ProgramFiles, 0)
	if e != nil {
		return e
	}
	dir := filepath.Join(pf, "Chameleon VPN")
	exe := filepath.Join(dir, "ChameleonBroker.exe")
	legacy := syscall.EscapeArg(filepath.Join(dir, "Chameleon.exe")) + " -broker-service"
	expected := syscall.EscapeArg(exe) + " -broker-service"
	m, e := mgr.Connect()
	if e != nil {
		return fmt.Errorf("open SCM (administrator rights required): %w", e)
	}
	defer m.Disconnect()
	s, e := m.OpenService(serviceName)
	if e != nil && !errors.Is(e, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
		return fmt.Errorf("open broker: %w", e)
	}
	exists := e == nil
	if exists {
		defer s.Close()
		c, e := s.Config()
		if e != nil {
			return e
		}
		if !strings.EqualFold(strings.TrimSpace(c.BinaryPathName), expected) && !strings.EqualFold(strings.TrimSpace(c.BinaryPathName), legacy) {
			return errors.New("unrelated ChameleonBroker ImagePath; refusing to change it")
		}
	}
	if action == "stop" || action == "remove" {
		if !exists {
			return nil
		}
		if e = stop(s); e != nil {
			return e
		}
		if action == "remove" {
			return s.Delete()
		}
		return nil
	}
	if action == "start" {
		if !exists {
			return errors.New("broker not installed")
		}
		st, e := s.Query()
		if e != nil {
			return e
		}
		if st.State == svc.Running {
			return nil
		}
		if e = s.Start(); e != nil && !errors.Is(e, windows.ERROR_SERVICE_ALREADY_RUNNING) {
			return e
		}
		return wait(s, svc.Running)
	}
	if action != "install" {
		return errors.New("unsupported action")
	}
	resolved, e := filepath.EvalSymlinks(exe)
	if e != nil {
		return fmt.Errorf("installed executable unavailable: %w", e)
	}
	if !strings.EqualFold(resolved, exe) {
		return errors.New("reparse-point installation paths are not supported")
	}
	c := mgr.Config{StartType: mgr.StartAutomatic, ErrorControl: mgr.ErrorNormal, ServiceType: windows.SERVICE_WIN32_OWN_PROCESS, ServiceStartName: "LocalSystem", DisplayName: "Chameleon VPN broker", Description: "Privileged tunnel broker for the standard-user Chameleon VPN application."}
	created := false
	if exists {
		if e = stop(s); e != nil {
			return e
		}
		c.BinaryPathName = expected
		e = s.UpdateConfig(c)
	} else {
		// The Windows API receives a properly escaped executable and a separate argument.
		s, e = m.CreateService(serviceName, exe, c, "-broker-service")
		if e == nil {
			created = true
			defer s.Close()
		}
	}
	if e != nil {
		return fmt.Errorf("register broker: %w", e)
	}
	if e = protect(s); e == nil {
		e = s.SetRecoveryActions([]mgr.RecoveryAction{{Type: mgr.ServiceRestart, Delay: 10 * time.Second}, {Type: mgr.ServiceRestart, Delay: 30 * time.Second}, {Type: mgr.NoAction}}, 86400)
	}
	if e != nil {
		if created {
			_ = s.Delete()
		}
		return fmt.Errorf("secure broker: %w", e)
	}
	fmt.Println("Broker registered and protected; VPN connection was not started.")
	return nil
}
func main() {
	action := flag.String("action", "", "install, stop, start or remove")
	flag.Parse()
	if e := perform(*action); e != nil {
		fmt.Fprintf(os.Stderr, "Chameleon broker %s: %v\n", *action, e)
		os.Exit(1)
	}
}
