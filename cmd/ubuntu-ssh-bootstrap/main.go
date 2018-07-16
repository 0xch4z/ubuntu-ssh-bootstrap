package main

import (
	"bufio"
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
	"runtime"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/terminal"
)

// config options
var sclient *client

var (
	userOption = &option{
		Name:    "user",
		Usage:   "User to ssh in as",
		Default: "root",
	}
	newUserOption = &option{
		Name:  "new-user",
		Usage: "New user to create",
	}
	hostOption = &option{
		Name:     "host",
		Usage:    "IP address or domain name of the target server",
		Required: true,
	}
	portOption = &option{
		Name:    "port",
		Usage:   "Port to use for SSH",
		Default: "22",
	}
	sshOnlyOption = &optionBool{
		Name:    "ssh-only",
		Usage:   "Configure server to only except ssh authentication",
		Default: false,
	}
)

type configOpt interface {
	Resolve()
	Validate()
}

type stringValidator func(string) error
type optionValidator func(string) error
type optionBoolValidator func(bool) error

type option struct {
	Name       string
	Usage      string
	Default    string
	Required   bool
	Value      string
	Validators []optionValidator
}

func (opt *option) IsNil() bool {
	return len(opt.Value) == 0
}

func (opt *option) Resolve() {
	flag.StringVar(&opt.Value, opt.Name, opt.Default, opt.Usage)
}

func (opt *option) Validate() {
	if opt.IsNil() && opt.Required {
		log.Fatalf("Error: option `%s` is required", opt.Name)
	}

	for _, validator := range opt.Validators {
		err := validator(opt.Value)
		if err != nil {
			log.Fatal(err.Error())
		}
	}
}

type optionBool struct {
	Name       string
	Usage      string
	Default    bool
	Required   bool
	Value      bool
	Validators []optionBoolValidator
}

func (opt *optionBool) Resolve() {
	flag.BoolVar(&opt.Value, opt.Name, opt.Default, opt.Usage)
}

func (opt *optionBool) Validate() {
	for _, validator := range opt.Validators {
		err := validator(opt.Value)
		if err != nil {
			log.Fatal(err.Error())
		}
	}
}

type client struct {
	handle *ssh.Client
}

func (c *client) user() string {
	return c.handle.Conn.User()
}

func (c *client) addr() string {
	return c.handle.Conn.RemoteAddr().String()
}

func (c *client) doesUserExist(name string) bool {
	cmd := fmt.Sprintf("echo $(id -u %s > /dev/null 2>&1; echo $?)", name)
	return !c.executeCommandBool(cmd)
}

func (c *client) createUser(name, password string) {
	cmd := fmt.Sprintf(
		`useradd %[1]s && \
		echo %[1]s:%[2]s | chpasswd && \
		sudo mkdir /home/%[1]s && \
		sudo chown %[1]s:%[1]s /home/%[1]s`, name, password)
	_ = c.executeCommand(cmd)
}

func (c *client) logExecutionError(cmd string, err error) {
	log.Fatalf("Error executing command `%s` on %s@%s: %s\n", cmd, c.user(), c.addr(), err.Error())
}

func (c *client) executeCommand(cmd string) string {
	sess, err := c.handle.NewSession()
	if err != nil {
		c.logExecutionError(cmd, err)
	}
	defer sess.Close()

	var (
		stdoutBuf bytes.Buffer
		stderrBuf bytes.Buffer
	)

	sess.Stdout = &stdoutBuf
	sess.Stderr = &stderrBuf
	sess.Run(cmd)

	fmt.Printf("stdout => %s\nstderr => %s\n", stdoutBuf.String(), stderrBuf.String())

	err = wrapStderr(stderrBuf)
	if err != nil {
		c.logExecutionError(cmd, err)
	}

	return stdoutBuf.String()
}

func (c *client) executeCommandBool(cmd string) bool {
	res := c.executeCommand(cmd)

	bres, _ := strconv.ParseBool(strings.TrimSpace(res))
	return bres
}

func resolveOptions() {
	opts := []configOpt{
		userOption,
		newUserOption,
		hostOption,
		portOption,
		sshOnlyOption,
	}

	for _, opt := range opts {
		opt.Resolve()
	}

	flag.Parse()

	for _, opt := range opts {
		opt.Validate()
	}
}

func promptYesOrNo(msg string) bool {
	reader := bufio.NewReader(os.Stdin)
	for {
		fmt.Printf("%s (y/n): ", msg)
		input, err := reader.ReadString('\n')
		if err != nil {
			// @TODO clean this up
			log.Fatal(err)
			continue
		}

		input = strings.ToLower(strings.TrimSpace(input))
		switch {
		case input == "y" || input == "yes":
			return true
		case input == "n" || input == "no":
			return false
		default:
			continue
		}
	}
}

func readPassword() string {
	fmt.Printf("%s@%s's password: ", userOption.Value, hostOption.Value)
	bPass, err := terminal.ReadPassword(int(syscall.Stdin))
	fmt.Println()

	if err != nil {
		log.Fatal("could not read password")
	}

	return string(bPass)
}

func readNewPassword() string {
	var newPassword string
	for {
		fmt.Printf("enter password for new user %s@%s: ", newUserOption.Value, hostOption.Value)
		bNewPassword, err := terminal.ReadPassword(int(syscall.Stdin))
		fmt.Println()
		if err != nil {
			fmt.Print("could not read password\n\n")
			continue
		}
		newPassword = string(bNewPassword)

		fmt.Printf("confirm password for new user %s@%s: ", newUserOption.Value, hostOption.Value)
		confirmed, err := terminal.ReadPassword(int(syscall.Stdin))
		fmt.Println()
		if err != nil {
			fmt.Print("could not read password\n\n")
			continue
		}

		if string(confirmed) != newPassword {
			fmt.Print("passwords did not match\n\n")
			continue
		}

		return newPassword
	}
}

func dial() *client {
	pw := readPassword()
	sshConf := &ssh.ClientConfig{
		User: userOption.Value,
		Auth: []ssh.AuthMethod{
			ssh.Password(pw),
		},
		HostKeyCallback: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			return nil
		},
	}
	host := fmt.Sprintf("%s:%s", hostOption.Value, portOption.Value)

	conn, err := ssh.Dial("tcp", host, sshConf)
	if err != nil {
		log.Fatal(err.Error())
	}

	return &client{conn}
}

func wrapStderr(stderr bytes.Buffer) error {
	str := stderr.String()
	if len(str) != 0 {
		return errors.New(str)
	}
	return nil
}

func getHomeDir() string {
	if runtime.GOOS == "windows" {
		home := os.Getenv("HOMEDRIVE") + os.Getenv("HOMEPATH")
		if home == "" {
			home = os.Getenv("USERPROFILE")
		}
		return home
	}
	return os.Getenv("HOME")
}

func getSSHDir() string {
	return getHomeDir() + "/.ssh"
}

func doesSSHDirExist() bool {
	sshDir := getSSHDir()

	if _, err := os.Stat(sshDir); os.IsNotExist(err) {
		return false
	}
	return true
}

func makeSSHDir() {
	os.MkdirAll(getSSHDir(), os.ModePerm)
}

func createSSHKeyPair(name string) {
	sshDir := getSSHDir()

	if _, err := os.Stat(sshDir + name); err == nil {
		fmt.Println("")
	}
}

func getSSHKeys() []string {
	sshDir := getSSHDir()

	files, err := ioutil.ReadDir(sshDir)
	if err != nil {
		log.Fatal("Error getting SSH keys:", err.Error())
	}

	var fnames []string
	for _, f := range files {
		fnames = append(fnames, f.Name())
	}

	return fnames
}

func init() {
	resolveOptions()
}

func createNewUserIfNeeded() {
	if !newUserOption.IsNil() {
		uname := newUserOption.Value
		if sclient.doesUserExist(uname) {
			log.Fatalf("user `%s@%s` already exists\n", uname, sclient.addr())
		}
		pw := readNewPassword()

		sclient.createUser(uname, pw)
	}
}

func main() {
	sclient = dial()
	fmt.Printf("successfully authenticated as %s@%s\n", sclient.user(), sclient.addr())

	createNewUserIfNeeded()

	// res := sclient.executeCommand("ls")
	// fmt.Println(res)
	fmt.Println(getSSHKeys())
}
