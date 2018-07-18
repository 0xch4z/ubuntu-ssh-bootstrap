package main

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
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
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/terminal"
)

var sclient *client

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
		Default: true,
	}
	disableRootLoginOption = &optionBool{
		Name:    "no-root",
		Usage:   "Disable logging in as `root` via SSH",
		Default: false,
	}
	sshKeySizeOption = &optionInt{
		Name:    "key-size",
		Usage:   "Bit size for RSA SSH key to generate",
		Default: 4096,
		Validators: []optionIntValidator{
			func(n int) error {
				if n < 0 {
					return errors.New("`key-size` must be a positive integer")
				}
				return nil
			},
		},
	}
)

// ssh files/paths
const (
	sshConfigDir          = "/etc/ssh"
	sshConfigFile         = "/etc/ssh/sshd_config"
	sshDir                = "~/.ssh"
	sshIDRSAFile          = "~/.ssh/id_rsa"
	sshAuthorizedKeysFile = "~/.ssh/authorized_keys"
)

type configOpt interface {
	Resolve()
	Validate()
}

type stringValidator func(string) error
type optionValidator func(string) error
type optionIntValidator func(int) error
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

type optionInt struct {
	Name       string
	Usage      string
	Default    int
	Required   bool
	Value      int
	Validators []optionIntValidator
}

func (opt *optionInt) Resolve() {
	flag.IntVar(&opt.Value, opt.Name, opt.Default, opt.Usage)
}

func (opt *optionInt) Validate() {
	for _, validator := range opt.Validators {
		err := validator(opt.Value)
		if err != nil {
			log.Fatal(err.Error())
		}
	}
}

type privateKey struct {
	*rsa.PrivateKey
}

func (pk *privateKey) writeToFile(path string) {
	outf, err := os.Create(path)
	if err != nil {
		log.Fatalf("could create file `%s` for private key: %s \n", path, err.Error())
	}
	defer outf.Close()

	key := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(pk.PrivateKey),
	}

	err = pem.Encode(outf, key)
	if err != nil {
		log.Fatalf("could not encode private key to file `%s`: %s\n", path, err.Error())
	}

	fmt.Printf("private key has been saved to: `%s`\n", path)
}

func (pk *privateKey) writePublicKeyToFile(path string) {
	outf, err := os.Create(path + ".pub")
	if err != nil {
		log.Fatalf("could create file `%s.pub` for public key: %s \n", path, err.Error())
	}
	defer outf.Close()

	asn1Bytes, err := asn1.Marshal(pk.PublicKey)
	if err != nil {
		log.Fatalln("could not marshall puk", err.Error())
	}

	key := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: asn1Bytes,
	}

	err = pem.Encode(outf, key)
	if err != nil {
		log.Fatalf("could not encode public key to file `%s`: %s\n", path, err.Error())
	}

	fmt.Printf("public key has been saved to: `%s`\n", path)
}

func (pk *privateKey) writeKeyPairToFiles(basename string) {
	pk.writeToFile(basename)
	pk.writePublicKeyToFile(basename)
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

func (c *client) doesFileExist(path string) bool {
	cmd := fmt.Sprintf("echo $([ -f %s ] && echo 1 || echo 0)", path)
	return c.executeCommandBool(cmd)
}

func (c *client) doesDirExist(path string) bool {
	cmd := fmt.Sprintf("echo $([ -d %s ] && echo 1 || echo 0)", path)
	return c.executeCommandBool(cmd)
}

func (c *client) mkdir(dirs ...string) {
	dirStr := strings.Join(dirs, " ")
	cmd := fmt.Sprintf("mkdir %s", dirStr)
	_ = c.executeCommand(cmd)
}

func (c *client) touch(files ...string) {
	fileStr := strings.Join(files, " ")
	cmd := fmt.Sprintf("touch %s", fileStr)
	_ = c.executeCommand(cmd)
}

func (c *client) appendToFile(fname, content string) {
	if !c.doesFileExist(fname) {
		log.Fatalf("could not append to file `%s`; no such file exists\n", fname)
	}

	cmd := fmt.Sprintf("echo \"%s\" >> %s", escapeDoubleQuotedStr(content), fname)
	_ = c.executeCommand(cmd)
}

func (c *client) createAuthorizedKeysIfNeeded() {
	if !c.doesDirExist(sshDir) {
		c.mkdir(sshDir)
	}

	if !c.doesFileExist(sshAuthorizedKeysFile) {
		c.touch(sshAuthorizedKeysFile)
	}
}

func (c *client) addAuthorizedKey(pukStr string) {
	c.appendToFile(sshAuthorizedKeysFile, pukStr)
}

func (c *client) createSSHConfigIfNeeded() {
	if !c.doesFileExist(sshConfigFile) {
		c.touch(sshConfigFile)
	}
}

func (c *client) disableSSHPasswordAuth() {
	ln := wrapConfigLine("PasswordAuthentication no",
		"because you chose to disable clear-text password authentication over SSH")
	c.appendToFile(sshConfigFile, ln)
}

func (c *client) disableSSHRootLogin() {
	ln := wrapConfigLine("PermitRootLogin no",
		"because you chose to disable authenticating as `root` user over SSH")
	c.appendToFile(sshConfigFile, ln)
}

func (c *client) doesUserExist(name string) bool {
	cmd := fmt.Sprintf("echo $(id -u %s > /dev/null 2>&1; echo $?)", name)
	return !c.executeCommandBool(cmd)
}

func (c *client) createUser(name, password string) {
	cmd := fmt.Sprintf(
		`useradd %[1]s --system && \
		echo %[1]s:%[2]s | chpasswd && \
		sudo mkdir /home/%[1]s && \
		sudo chown %[1]s:%[1]s /home/%[1]s && \
		su %[1]s`, name, password)
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

func (c *client) changeUser(uname string) {
	if !c.doesUserExist(uname) {
		log.Fatalf("cannot change to user `%s`; no such user\n", uname)
	}

	_ = c.executeCommand("su " + uname)
}

func (c *client) restartSSH() {
	_ = c.executeCommand("service ssh")
}

func resolveOptions() {
	opts := []configOpt{
		userOption,
		newUserOption,
		hostOption,
		portOption,
		sshOnlyOption,
		disableRootLoginOption,
		sshKeySizeOption,
	}

	for _, opt := range opts {
		opt.Resolve()
	}

	flag.Parse()

	for _, opt := range opts {
		opt.Validate()
	}
}

func prompt(msg string) string {
	reader := bufio.NewReader(os.Stdin)
	res, _ := reader.ReadString('\n')
	return res
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

func wrapConfigLine(line string, notes ...string) string {
	for i, str := range notes {
		if i == 0 {
			str = "\n" + str
		}
		notes[i] = strings.Replace(str, "\n", "\n### ", -1)
	}
	noteStr := strings.Join(notes, "\n### ")
	now := time.Now()
	nowStr := now.Format("2006-01-02 15:04:05")

	return fmt.Sprintf("### start: generated on %s by ubuntu-secure-bootstrap%s ###\n%s\n### end ###\n",
		nowStr, noteStr, line)
}

func escapeDoubleQuotedStr(str string) string {
	return strings.Replace(str, "\"", "\\\"", -1)
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

func generatePrivateKey(bitSize int) (*privateKey, error) {
	prk, err := rsa.GenerateKey(rand.Reader, bitSize)
	if err != nil {
		return nil, err
	}

	err = prk.Validate()
	if err != nil {
		return nil, err
	}

	return &privateKey{prk}, nil
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

func createNewUserIfNeeded() {
	if !newUserOption.IsNil() {
		uname := newUserOption.Value
		if sclient.doesUserExist(uname) {
			log.Fatalf("user `%s@%s` already exists\n", uname, sclient.addr())
		}
		pw := readNewPassword()

		sclient.createUser(uname, pw)
		sclient.changeUser(uname)
	}
}

func authorizeHost(pukStr string) {
	sclient.createAuthorizedKeysIfNeeded()
	sclient.addAuthorizedKey(pukStr)
}

func forceSSHAuthIfNeeded() {
	if sshOnlyOption.Value {
		sclient.createSSHConfigIfNeeded()
		sclient.disableSSHPasswordAuth()
	}
}

func disableSSHRootLoginIfNeeded() {
	if disableRootLoginOption.Value {
		sclient.createSSHConfigIfNeeded()
		sclient.disableSSHRootLogin()
	}
}

func getPublicSSHKey() string {
	var fname string

	if !doesSSHDirExist() {
		makeSSHDir()
	}

	hasIDRSAKey := false
	sshDir := getSSHDir()
	keys := getSSHKeys()
	for _, key := range keys {
		if key == "id_rsa.pub" {
			hasIDRSAKey = true
		}
	}

	if hasIDRSAKey {
		fname = "id_rsa.pub"
	} else {
		res := promptYesOrNo("Could not find an `id_rsa` SSH key, want me to generate an SSH key?")
		if res {
			name := prompt("SSH key name")
			priv, err := generatePrivateKey(sshKeySizeOption.Value)
			if err != nil {
				log.Fatalln("Could not generate private key:", err.Error())
			}

			priv.writeKeyPairToFiles(name)
			fname = name + ".pub"
		}
	}

	fpath := fmt.Sprintf("%s/%s", sshDir, fname)
	pukBytes, err := ioutil.ReadFile(fpath)
	if err != nil {
		log.Fatalf("could not read public key `%s`: %s\n", fpath, err.Error())
	}
	return string(pukBytes)
}

func init() {
	resolveOptions()
}

func main() {
	sclient = dial()
	fmt.Printf("successfully authenticated as %s@%s\n", sclient.user(), sclient.addr())

	puk := getPublicSSHKey()
	forceSSHAuthIfNeeded()
	disableSSHRootLoginIfNeeded()
	createNewUserIfNeeded()
	authorizeHost(puk)
	sclient.restartSSH()
}
