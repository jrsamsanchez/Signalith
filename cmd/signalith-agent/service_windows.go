//go:build windows

package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/jrsamsanchez/signalith/internal/agentd"
	"github.com/jrsamsanchez/signalith/internal/safelog"
	"golang.org/x/sys/windows/svc"
)

// serviceName is the service the Windows install script
// (deploy/agent/install.ps1) makes.
const serviceName = "SignalithAgent"

// runService runs the service handler when Windows started this program
// as a service, and is false otherwise. It is called from main, not init:
// Windows calls the handler on a thread of its own, which Go holds until
// package init is done.
func runService() bool {
	isSvc, err := svc.IsWindowsService()
	if err != nil || !isSvc {
		return false
	}
	if err := svc.Run(serviceName, &service{paths: agentd.DefaultPaths()}); err != nil {
		os.Exit(1)
	}
	return true
}

type service struct{ paths agentd.Paths }

// stopWait is how long a stop may take: the agent stops Fluent Bit,
// which it gives 10 seconds.
const stopWait = 30 * time.Second

func (s *service) Execute(_ []string, req <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	status <- svc.Status{State: svc.StartPending}
	// A service has no console: the agent logs to agent.log in its state
	// folder, which rotates by size so it cannot fill the disk.
	var w io.Writer = io.Discard
	if f, err := safelog.OpenRotating(filepath.Join(s.paths.State, "agent.log"), safelog.DefaultMaxSize, safelog.DefaultBackups); err == nil {
		defer f.Close()
		w = f
	}
	a, err := newAgent(s.paths, w)
	if err != nil {
		// Stops the service before it reports running, so the Services
		// console and the install script see it failed.
		fmt.Fprintln(w, "signalith-agent: cannot start:", err)
		return false, 1
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- a.Run(ctx) }()
	status <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	for {
		select {
		case err := <-done:
			if err != nil {
				fmt.Fprintln(w, "signalith-agent: stopped:", err)
				return false, 1
			}
			return false, 0
		case c := <-req:
			switch c.Cmd {
			case svc.Interrogate:
				status <- c.CurrentStatus
			case svc.Stop, svc.Shutdown:
				cancel()
				status <- svc.Status{State: svc.StopPending, WaitHint: uint32(stopWait / time.Millisecond)}
				select {
				case <-done:
				case <-time.After(stopWait):
				}
				return false, 0
			}
		}
	}
}

// agentService is the agent's Windows service.
func agentService(p agentd.Paths) agentd.ServiceControl {
	return agentd.WindowsService{Name: p.Service}
}

// updateLog is the updater's log, updater.log in the agent's state
// folder: the updater runs on its own, with no console.
func updateLog(p agentd.Paths, w io.Writer) io.Writer {
	f, err := safelog.OpenRotating(filepath.Join(p.State, "updater.log"), safelog.DefaultMaxSize, safelog.DefaultBackups)
	if err != nil {
		return w
	}
	return f
}

// agentLog is w: the service writes agent.log itself (service.Execute).
func agentLog(_ agentd.Paths, w io.Writer) io.Writer { return w }
