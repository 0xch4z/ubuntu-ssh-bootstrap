package main

import (
	"bufio"
	"bytes"
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

func (c *client) executeCommand(cmd string) (string, error) {
	sess, err := c.handle.NewSession()
	if err != nil {
		return "", err
	}
	defer sess.Close()

	var stdoutBuf bytes.Buffer
	sess.Stdout = &stdoutBuf
	sess.Run(cmd)

	return stdoutBuf.String(), nil
}

func (c *client) executeCommandBool(cmd string) (bool, error) {
	res, err := c.executeCommand(cmd)
	if err != nil {
		return false, err
	}

	bres, _ := strconv.ParseBool(res)
	return bres, nil
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

func dial() *client {
	pw := readPassword()
	sshConf := &ssh.ClientConfig{
		User: userOption.Value,
		Auth: []ssh.AuthMethod{
			ssh.Password(pw),
		},
		HostKeyCallback: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			fmt.Printf("\nSuccessfully connected to %s\n\n", hostname)
			return nil
		},
	}
	fmt.Println(hostOption.Value, portOption.Value)
	host := fmt.Sprintf("%s:22", hostOption.Value)

	conn, err := ssh.Dial("tcp", host, sshConf)
	if err != nil {
		log.Fatal(err.Error())
	}

	return &client{conn}
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

func main() {
	client := dial()
	res, err := client.executeCommand("lkkks")
	if err != nil {
		log.Fatal(err.Error())
	}

	fmt.Println(res)
	fmt.Println(getSSHKeys())
}
