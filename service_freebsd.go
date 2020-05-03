package service

import (
	//"bytes"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"text/template"
	//"time"
	"io/ioutil"
	"log/syslog"
	"os/exec"
	"strings"


)

const maxPathSize = 32 * 1024

const version = "freebsd-rcd"

type freebsdSystem struct{}

func (freebsdSystem) String() string {
	return version
}
func (freebsdSystem) Detect() bool {
	return true
}
func (freebsdSystem) Interactive() bool {
	return interactive
}
func (freebsdSystem) New(i Interface, c *Config) (Service, error) {
	s := &freebsdRcdService{
		i:      i,
		Config: c,

		userService: c.Option.bool(optionUserService, optionUserServiceDefault),
	}

	return s, nil
}

func init() {
	ChooseSystem(freebsdSystem{})
}

var interactive = false

func init() {
	var err error
	interactive, err = isInteractive()
	if err != nil {
		panic(err)
	}
}

func isInteractive() (bool, error) {
	// TODO: The PPID of Launchd is 1. The PPid of a service process should match launchd's PID.
	return os.Getppid() != 1, nil
}

type freebsdRcdService struct {
	i Interface
	*Config

	userService bool
}

func (s *freebsdRcdService) String() string {
	if len(s.DisplayName) > 0 {
		return s.DisplayName
	}
	return s.Name
}

func (s *freebsdRcdService) getServiceFilePath() (string, error) {

	return "/etc/rc.d/" + s.Name , nil
}

func (s *freebsdRcdService) Install() error {

	confPath, err := s.getServiceFilePath()
	if err != nil {
		return err
	}
	_, err = os.Stat(confPath)
	if err == nil {
		return fmt.Errorf("Init already exists: %s", confPath)
	}

	if s.userService {
		// Ensure that ~/Library/LaunchAgents exists.
		err = os.MkdirAll(filepath.Dir(confPath), 0700)
		if err != nil {
			return err
		}
	}

	f, err := os.Create(confPath)
	if err != nil {
		return err
	}
	defer f.Close()

	path, err := s.execPath()
	if err != nil {
		return err
	}

	var to = &struct {
		*Config
		Path string

		KeepAlive, RunAtLoad bool
		SessionCreate        bool
	}{
		Config:        s.Config,
		Path:          path,
		KeepAlive:     s.Option.bool(optionKeepAlive, optionKeepAliveDefault),
		RunAtLoad:     s.Option.bool(optionRunAtLoad, optionRunAtLoadDefault),
		SessionCreate: s.Option.bool(optionSessionCreate, optionSessionCreateDefault),
	}

	functions := template.FuncMap{
		"bool": func(v bool) string {
			if v {
				return "true"
			}
			return "false"
		},
	}

	name := s.Name
	serviceName := strings.Replace(name, "-", "_",-1)
	serviceRcvar := serviceName + "_enable"

	serviceScript := strings.Replace(rcdScriptOpsramp, "serviceNameToReplace", serviceName,-1)
	serviceScript = strings.Replace(serviceScript, "rcvarToReplace", serviceRcvar,-1)
	serviceScript = strings.Replace(serviceScript, "commandToReplace", path,-1)
	if len(s.Config.Arguments)==0{
		serviceScript = strings.Replace(serviceScript, "argumentsToReplace", "",-1)
	}else{
		serviceScript = strings.Replace(serviceScript, "argumentsToReplace", s.Config.Arguments[0],-1)

	}

	file, err := os.OpenFile("/etc/rc.conf", os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		fmt.Errorf("failed opening file: %s", err)
		}
		defer file.Close()
	data :=  serviceRcvar + "="+`"`+"YES"+`"`
	fmt.Fprintln(file, data)

	t := template.Must(template.New("serviceScript").Funcs(functions).Parse(serviceScript))
	errExecute := t.Execute(f, to)

	serviceName = "/etc/rc.d/" + s.Name
	err = os.Chmod(serviceName, 755)
	if err != nil {
		fmt.Errorf("Not able to give permission")
	}

	return errExecute
}

func (s *freebsdRcdService) Uninstall() error {
	s.Stop()

	name := s.Name
	serviceName := strings.Replace(name, "-", "_",-1)
	serviceRcvar := serviceName + "_enable"

	serviceToDisable := "'/" + serviceRcvar + "/d'"

	run("sed", "-i", "-e", serviceToDisable, "/etc/rc.conf")

	confPath, err := s.getServiceFilePath()
	if err != nil {
		return err
	}
	return os.Remove(confPath)
}

func (s *freebsdRcdService) Start() error {
	return run("service", s.Name, "start")
}
func (s *freebsdRcdService) Stop() error {
	return run("service",  s.Name, "stop")

}
func (s *freebsdRcdService) Restart() error {
	return run("service", s.Name, "restart")

}

func (s *freebsdRcdService) Run() error {
	var err error

	err = s.i.Start(s)
	if err != nil {
		return err
	}

	s.Option.funcSingle(optionRunWait, func() {
		var sigChan = make(chan os.Signal, 3)
		signal.Notify(sigChan, syscall.SIGTERM, os.Interrupt)
		<-sigChan
	})()

	return s.i.Stop(s)
}

func (s *freebsdRcdService) Logger(errs chan<- error) (Logger, error) {
	if interactive {
		return ConsoleLogger, nil
	}
	return s.SystemLogger(errs)
}
func (s *freebsdRcdService) SystemLogger(errs chan<- error) (Logger, error) {
	return newSysLogger(s.Name, errs)
}


const rcdScriptOpsramp = `
#!/bin/sh
. /etc/rc.subr

name=serviceNameToReplace
rcvar=rcvarToReplace
command=commandToReplace
command_args=argumentsToReplace
pidfile="/var/run/${name}.pid"

start_cmd="test_start"
stop_cmd="test_stop"
status_cmd="test_status"

test_start() {
    /usr/sbin/daemon -p ${pidfile} ${command} ${command_args}
}

test_status() {
    if [ -e ${pidfile} ]; then
        echo ${name} is running...
    else
        echo ${name} is not running.
    fi
}

test_stop() {
    if [ -e ${pidfile} ]; then` + "\n" +
"        PID=`cat ${pidfile}`" + "\n" +
	`    else
        echo ${name} is not running?
    fi
    kill -0 $PID 2>/dev/null
    if [ $? -eq 0 ]; then
        kill $PID;
        sleep 1
        kill -0 $PID 2>/dev/null
        if [ $? -eq 0 ]; then
            sleep 4
            kill -0 $PID 2>/dev/null
            if [ $? -eq 0 ]; then
                kill -9 $PID;
                echo "${name} killed using signal 9 SIGKILL"
            fi
        fi
    else
        echo ${name} is not running?
    fi
}

load_rc_config $name
run_rc_command "$1"
`

func newSysLogger(name string, errs chan<- error) (Logger, error) {
	w, err := syslog.New(syslog.LOG_INFO, name)
	if err != nil {
		return nil, err
	}
	return sysLogger{w, errs}, nil
}

type sysLogger struct {
	*syslog.Writer
	errs chan<- error
}

func (s sysLogger) send(err error) error {
	if err != nil && s.errs != nil {
		s.errs <- err
	}
	return err
}

func (s sysLogger) Error(v ...interface{}) error {
	return s.send(s.Writer.Err(fmt.Sprint(v...)))
}
func (s sysLogger) Warning(v ...interface{}) error {
	return s.send(s.Writer.Warning(fmt.Sprint(v...)))
}
func (s sysLogger) Info(v ...interface{}) error {
	return s.send(s.Writer.Info(fmt.Sprint(v...)))
}
func (s sysLogger) Errorf(format string, a ...interface{}) error {
	return s.send(s.Writer.Err(fmt.Sprintf(format, a...)))
}
func (s sysLogger) Warningf(format string, a ...interface{}) error {
	return s.send(s.Writer.Warning(fmt.Sprintf(format, a...)))
}
func (s sysLogger) Infof(format string, a ...interface{}) error {
	return s.send(s.Writer.Info(fmt.Sprintf(format, a...)))
}

func run(command string, arguments ...string) error {
	cmd := exec.Command(command, arguments...)

	// Connect pipe to read Stderr
	stderr, err := cmd.StderrPipe()

	if err != nil {
		// Failed to connect pipe
		return fmt.Errorf("%q failed to connect stderr pipe: %v", command, err)
	}

	// Do not use cmd.Run()
	if err := cmd.Start(); err != nil {
		// Problem while copying stdin, stdout, or stderr
		return fmt.Errorf("%q failed: %v", command, err)
	}

	// Zero exit status
	// Darwin: launchctl can fail with a zero exit status,
	// so check for emtpy stderr
	if command == "launchctl" {
		slurp, _ := ioutil.ReadAll(stderr)
		if len(slurp) > 0 {
			return fmt.Errorf("%q failed with stderr: %s", command, slurp)
		}
	}

	if err := cmd.Wait(); err != nil {
		// Command didn't exit with a zero exit status.
		return fmt.Errorf("%q failed: %v", command, err)
	}

	return nil
}

