![Test Actions](https://github.com/yuchanns/srslog/workflows/test/badge.svg?branch=master)
![GitHub tag (latest by date)](https://img.shields.io/github/v/tag/yuchanns/srslog)
![Go version](https://img.shields.io/github/go-mod/go-version/yuchanns/srslog)
[![Go Reference](https://pkg.go.dev/badge/github.com/yuchanns/srslog.svg)](https://pkg.go.dev/github.com/yuchanns/srslog)
[![codecov](https://codecov.io/gh/yuchanns/srslog/branch/master/graph/badge.svg?token=7Y7QYFRXUG)](https://codecov.io/gh/yuchanns/srslog)

# srslog

Go has a `syslog` package in the standard library, but it has the following
shortcomings:

1. It doesn't have TLS support
2. [According to bradfitz on the Go team, it is no longer being maintained.](https://github.com/golang/go/issues/13449#issuecomment-161204716)

I agree that it doesn't need to be in the standard library. So, I've
followed Brad's suggestion and have made a separate project to handle syslog.

This code was taken directly from the Go project as a base to start from.

However, this _does_ have TLS support.

# Usage

Basic usage retains the same interface as the original `syslog` package. We
only added to the interface where required to support new functionality.

Switch from the standard library:

```
import(
    //"log/syslog"
    syslog "github.com/yuchanns/srslog"
)
```

You can still use it for local syslog:

```
w, err := syslog.Dial("", "", syslog.LOG_ERR, "testtag")
```

Or to unencrypted UDP:

```
w, err := syslog.Dial("udp", "192.168.0.50:514", syslog.LOG_ERR, "testtag")
```

Or to unencrypted TCP:

```
w, err := syslog.Dial("tcp", "192.168.0.51:514", syslog.LOG_ERR, "testtag")
```

But now you can also send messages via TLS-encrypted TCP:

```
w, err := syslog.DialWithTLSCertPath("tcp+tls", "192.168.0.52:514", syslog.LOG_ERR, "testtag", "/path/to/servercert.pem")
```

And if you need more control over your TLS configuration :

```
pool := x509.NewCertPool()
serverCert, err := ioutil.ReadFile("/path/to/servercert.pem")
if err != nil {
    return nil, err
}
pool.AppendCertsFromPEM(serverCert)
config := tls.Config{
    RootCAs: pool,
}

w, err := DialWithTLSConfig(network, raddr, priority, tag, &config)
```

(Note that in both TLS cases, this uses a self-signed certificate, where the
remote syslog server has the keypair and the client has only the public key.)

And then to write log messages, continue like so:

```
if err != nil {
    log.Fatal("failed to connect to syslog:", err)
}
defer w.Close()

w.Alert("this is an alert")
w.Crit("this is critical")
w.Err("this is an error")
w.Warning("this is a warning")
w.Notice("this is a notice")
w.Info("this is info")
w.Debug("this is debug")
w.Write([]byte("these are some bytes"))
```

If you need further control over connection attempts, you can use the DialWithCustomDialer
function. To continue with the DialWithTLSConfig example:

```
netDialer := &net.Dialer{Timeout: time.Second*5} // easy timeouts
realNetwork := "tcp" // real network, other vars your dail func can close over
dial := func(network, addr string) (net.Conn, error) {
    // cannot use "network" here as it'll simply be "custom" which will fail
    return tls.DialWithDialer(netDialer, realNetwork, addr, &config)
}

w, err := DialWithCustomDialer("custom", "192.168.0.52:514", syslog.LOG_ERR, "testtag", dial)
```

Your custom dial func can set timeouts, proxy connections, and do whatever else it needs before returning a net.Conn.

# Generating TLS Certificates

We've provided an example of go code that you can use to generate a self-signed keypair:

```
func KeyGen() (string, string, func() error, error) {
	// generate certificate
	baseDir := os.TempDir()
	baseNameByte := make([]byte, 5)
	if _, err := rand.Read(baseNameByte); err != nil {
		return "", "", nil, err
	}
	priPath := path.Join(baseDir, fmt.Sprintf("%X_pri.pem", baseNameByte))
	pubPath := path.Join(baseDir, fmt.Sprintf("%X_pub.pem", baseNameByte))

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", "", nil, err
	}

	keyOut, err := os.Create(priPath)
	if err != nil {
		return "", "", nil, err
	}
	defer keyOut.Close()
	// Generate a pem block with the private key
	if err := pem.Encode(keyOut, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	}); err != nil {
		return "", "", nil, err
	}
	tml := x509.Certificate{
		// you can add any attr that you need
		NotBefore: time.Now(),
		NotAfter:  time.Now().AddDate(5, 0, 0),
		// you have to generate a different serial number each execution
		SerialNumber: big.NewInt(123123),
		Subject: pkix.Name{
			CommonName:   "New Name",
			Organization: []string{"New Org."},
		},
		BasicConstraintsValid: true,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}
	cert, err := x509.CreateCertificate(rand.Reader, &tml, &tml, &key.PublicKey, key)
	if err != nil {
		return "", "", nil, err
	}

	certOut, err := os.Create(pubPath)
	if err != nil {
		return "", "", nil, err
	}
	defer certOut.Close()
	// Generate a pem block with the certificate
	if err := pem.Encode(certOut, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert,
	}); err != nil {
		return "", "", nil, err
	}

	return priPath, pubPath, func() error {
		if err := os.Remove(priPath); err != nil {
			return err
		}
		return os.Remove(pubPath)
	}, nil
}
```

That outputs the public key and private key will be put into `.pem` files which
placed under `/tmp`. (The certificate in is used by the unit tests, and please
do not actually use it anywhere else.)

# Running Tests

Run the tests as usual:

```
go test
```

Also a test coverage command will show you which
lines of code are not covered:

```
go test -v ./... -coverprofile coverage.out -covermode count
go tool cover -func coverage.out
```
# License

This project uses the New BSD License, the same as the Go project itself.

# Code of Conduct

Please note that this project is released with a Contributor Code of Conduct.
By participating in this project you agree to abide by its terms.
