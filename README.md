# go-nsdctl
Golang interface for NSD's control socket

# Usage
```go
package main

import (
  "io"
  "os"

  "github.com/optix2000/go-nsdctl"
)

func main() {
  client, err := nsdctl.NewClientFromConfig("/etc/nsd/nsd.conf")
  // If you want to build one manually
  // client, err := nsdctl.NewClient("127.0.0.1:8952", "nsd", "/etc/nsd/nsd_server.pem", "/etc/nsd/nsd_control.key", "/etc/nsd/nsd_control.pem", false)
  if err != nil {
    panic(err)
  }

  r, err := client.Command("status")
  if err != nil {
    panic(err)
  }

  io.Copy(os.Stdout, r)
}
```
