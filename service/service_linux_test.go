//go:build linux

// NOTE: requires flag '-gcflags=-l' to go test to work with monkey patching

package service

import (
	"github.com/Project-Faster/monkey"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
	"os"
	"os/exec"
	"syscall"
	"testing"
	"time"
)

func TestServiceLinuxSuite(t *testing.T) {
	var q ServiceLinuxSuite
	suite.Run(t, &q)
}

type ServiceLinuxSuite struct{ suite.Suite }

func (s *ServiceLinuxSuite) AfterTest(_, _ string) {
	monkey.UnpatchAll()
}

func (s *ServiceLinuxSuite) BeforeTest(_, _ string) {}

func (s *ServiceLinuxSuite) TestSetCurrentWorkingDir() {
	assert.NotPanics(s.T(), func() {
		assert.True(s.T(), setCurrentWorkingDir("no-op"))
	})
}

func (s *ServiceLinuxSuite) TestWaitChildProcessTermination() {
	assert.NotPanics(s.T(), func() {
		waitChildProcessTermination("no-op")
	})
}

func (s *ServiceLinuxSuite) TestSetServiceUserPermissions() {
	assert.NotPanics(s.T(), func() {
		setServiceUserPermissions("no-op")
	})
}

func (s *ServiceLinuxSuite) TestSetInstallDirectoryPermissions() {
	assert.NotPanics(s.T(), func() {
		setInstallDirectoryPermissions("no-op")
	})
}

func (s *ServiceLinuxSuite) TestSendProcessInterrupt() {
	var start = time.Now()

	routeCmd := exec.Command("bash", "-c", `sleep 30`)
	routeCmd.SysProcAttr = &syscall.SysProcAttr{}
	assert.Nil(s.T(), routeCmd.Start())

	monkey.Patch(os.Getpid, func() int {
		return routeCmd.Process.Pid
	})

	sendProcessInterrupt()

	assert.True(s.T(), time.Now().Before(start.Add(30*time.Second)))
}
