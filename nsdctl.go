package nsdctl

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"os"
	"path"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Constants
var supportedProtocols = map[string]protocol{
	"nsd":     {Prefix: "NSDCT", Version: 1, ServerName: "nsd", ErrorStr: "error"},
	"unbound": {Prefix: "UBCT", Version: 1, ServerName: "unbound", ErrorStr: "error"},
}

var configDefaults = map[string]config{
	// Taken from https://www.nlnetlabs.nl/projects/nsd/nsd.conf.5.html
	"nsd": {
		port: nsdConfig{
			"control-port",
			"8952",
		},
		caFile: nsdConfig{
			"server-cert-file",
			"/etc/nsd/nsd_server.pem",
		},
		keyFile: nsdConfig{
			"control-key-file",
			"/etc/nsd/nsd_control.key",
		},
		certFile: nsdConfig{
			"control-cert-file",
			"/etc/nsd/nsd_control.pem"},
	},
	// Taken from https://www.unbound.net/documentation/unbound.conf.html
	"unbound": {
		port: nsdConfig{
			"control-port",
			"8953",
		},
		caFile: nsdConfig{
			"server-cert-file",
			"unbound_server.pem",
		},
		keyFile: nsdConfig{
			"control-key-file",
			"unbound_control.key",
		},
		certFile: nsdConfig{
			"control-cert-file",
			"unbound_control.pem",
		},
	},
}

// Structs

// config contains the necessary config file values we want
type config struct {
	port     nsdConfig
	caFile   nsdConfig
	certFile nsdConfig
	keyFile  nsdConfig
}

// nsdConfig contains what the config file line looks like and the default
type nsdConfig struct {
	Config  string
	Default string
}

// protocol defines constants for each nsd-like protocol
type protocol struct {
	// Prefix defines the command prefix
	Prefix string
	// Version defines the command version
	Version uint
	// ServerName defines the expected certificate server name
	ServerName string
	// ErrorStr defines the response that signifies an error
	ErrorStr string
}

// NSDError defines an error type for NSD
type NSDError struct {
	err string
}

func (e *NSDError) Error() string {
	return e.err
}

// NSDClient is a client for NSD's control socket
type NSDClient struct {
	// TODO: Add in detection of type
	// HostString is the string used to connect
	HostString string
	// Dialer is dialer used to create the connection
	Dialer *net.Dialer
	// TLSClientConfig is the tls.Config for the connection
	TLSClientConfig *tls.Config
	// Connection is the raw net.Conn for the client
	Connection net.Conn
	// protocol is the NSD protocol type (see supportedProtocols)
	protocol *protocol
}

// NewClientFromConfig tries to autodetect and create a new NSDClient from an config file
func NewClientFromConfig(configPath string) (*NSDClient, error) {
	filename := path.Base(configPath)

	var detectedType string
	for k := range configDefaults {
		if strings.Contains(filename, k) {
			detectedType = k
		}
	}
	if detectedType == "" {
		fmt.Println("Could not detect type from config file")
		return nil, &NSDError{"Could not detect type from config file"}
	}

	file, err := os.Open(configPath)
	if err != nil {
		return nil, err
	}

	// TODO: Rewrite search section.
	// Minor optimization to precompile regex
	// More generic way of plugging matches to results
	// Also, flawed regexes won't match unicode names or other special characters

	conf := configDefaults[detectedType]
	rePort, err := regexp.Compile(conf.port.Config + ": *([0-9]+)(?:#.*)?")
	reCAFile, err := regexp.Compile(conf.caFile.Config + ": *([a-zA-Z0-9/]+)(?:#.*)?")
	reKeyFile, err := regexp.Compile(conf.keyFile.Config + ": *([a-zA-Z0-9/]+)(?:#.*)?")
	reCertFile, err := regexp.Compile(conf.certFile.Config + ": *([a-zA-Z0-9/]+)(?:#.*)?")

	var port uint
	var hostString, caFile, keyFile, certFile string

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()

		if port == 0 {
			res := rePort.FindStringSubmatch(line)
			if res != nil {
				port64, err := strconv.ParseUint(res[1], 10, 16)
				if err != nil {
					return nil, err
				}
				port = uint(port64)
			}
		}

		if caFile == "" {
			res := reCAFile.FindStringSubmatch(line)
			if res != nil {
				caFile = res[1]
			}
		}
		if keyFile == "" {
			res := reKeyFile.FindStringSubmatch(line)
			if res != nil {
				keyFile = res[1]
			}
		}
		if certFile == "" {
			res := reCertFile.FindStringSubmatch(line)
			if res != nil {
				certFile = res[1]
			}
		}
	}
	err = scanner.Err()
	if err != nil {
		return nil, err
	}

	if port != 0 {
		hostString = "127.0.0.1:" + string(port)
	}

	return NewClient(detectedType, hostString, caFile, keyFile, certFile, false)
}

// NewClient creates a complete new NSDClient and returns any errors encountered
func NewClient(serverType string, hostString string, caFile string, keyFile string, certFile string, skipVerify bool) (*NSDClient, error) {
	protocol, ok := supportedProtocols[serverType]
	if !ok {
		return nil, errors.New("Server Type not Supported")
	}

	// Defaults
	defaults := configDefaults[serverType]
	if hostString == "" {
		hostString = "127.0.0.1:" + defaults.port.Default
	}
	if caFile == "" {
		caFile = defaults.caFile.Default
	}
	if keyFile == "" {
		keyFile = defaults.keyFile.Default
	}
	if certFile == "" {
		certFile = defaults.certFile.Default
	}

	// Set up connection
	dialer := &net.Dialer{
		// TODO: Don't hardcode these
		Timeout: 1 * time.Second,
		// NSD 4.1.x doesn't allow more than one connection to the socket
		// and also closes connection after every command
		// so keepalive is useless
		KeepAlive: 0,
		DualStack: true,
	}

	client := &NSDClient{
		HostString: hostString,
		Dialer:     dialer,
		protocol:   &protocol,
	}

	clientCertKeyPair, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, err
	}

	rootCAs, err := x509.SystemCertPool()
	if err != nil {
		return nil, err
	}

	buf, err := ioutil.ReadFile(caFile)
	if err != nil {
		fmt.Println("Could not load provided CA certificate(s). Using only system CAs.")
	} else {
		ok = rootCAs.AppendCertsFromPEM(buf)
		if !ok {
			fmt.Println("Could not load provided CA certificate(s). Using only system CAs.")
		}
	}

	client.TLSClientConfig = &tls.Config{
		Certificates:       []tls.Certificate{clientCertKeyPair},
		RootCAs:            rootCAs,
		ServerName:         protocol.ServerName,
		InsecureSkipVerify: skipVerify,
	}

	r, err := client.Command("status")
	if err != nil {
		if r != nil {
			// Drain rest of reader
			io.Copy(ioutil.Discard, r)
		}
		return nil, err
	}

	return client, nil
}

// attempt to build a connection
// NB!: Assumes connection close
func (n *NSDClient) attemptConnection() error {
	// Cleanly close existing connections
	// NB!: NSD only allows one connection at a time.
	// Old connection MUST be closed before new one is made.
	if n.Connection != nil {
		n.Connection.Close()
	}

	conn, err := tls.DialWithDialer(n.Dialer, "tcp", n.HostString, n.TLSClientConfig)
	if err != nil {
		return err
	}

	n.Connection = conn
	return nil
}

// Command sends a command to the control socket
// Returns an io.Reader with the results of the command.
// error will contain any errors encountered (including invalid commands)
func (n *NSDClient) Command(command string) (io.Reader, error) {
	//TODO: Currently assumes connection close.
	// Should check if connection is available to use
	err := n.attemptConnection()
	if err != nil {
		return nil, err
	}

	// Format and send the command
	_, err = fmt.Fprintf(n.Connection, "%s%d %s\n", n.protocol.Prefix, n.protocol.Version, command)
	if err != nil {
		return nil, err
	}

	r := bufio.NewReader(n.Connection)
	err = n.peekError(r)
	return r, err
}

func (n *NSDClient) peekError(r *bufio.Reader) error {
	// Peek the scan buffer
	preString, err := r.Peek(len(n.protocol.ErrorStr))
	if err != nil {
		return err
	}

	if string(preString) == n.protocol.ErrorStr {
		line, _ := r.ReadString('\n')
		return &NSDError{line[:len(line)-1]}
	}
	return nil
}
