// Command containeridentity is used by scripts/test-container-identity.sh: it runs the container
// collector's reading and conversion (internal/containers) against the real Docker Engine, but
// only for the containers named on the command line (the test's own), so no other container on
// the machine is listed or read. For each one it writes <out>/<label>.txt: the status line, then
// the `#smoke-host 1` inventory. Test use only.
//
//	containeridentity -socket /var/run/docker.sock -out DIR label=<container id> ...
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"gitlab.aircraft.tw/smoke/smoke-collector/internal/containers"
	"gitlab.aircraft.tw/smoke/smoke-collector/internal/docker"
)

// only lists the given containers instead of asking the Engine for all of them.
type only struct {
	*docker.Client
	list []docker.Container
}

func (o only) Containers(context.Context) ([]docker.Container, error) { return o.list, nil }

func main() {
	socket := flag.String("socket", "/var/run/docker.sock", "Docker Engine socket")
	out := flag.String("out", "", "output directory")
	flag.Parse()
	ctx := context.Background()
	c := docker.New(*socket)
	if _, err := c.Version(ctx); err != nil {
		log.Fatal(err)
	}
	for _, arg := range flag.Args() {
		label, spec, ok := strings.Cut(arg, "=")
		parts := strings.Split(spec, ",") // id,imageID,image
		if !ok || len(parts) != 3 {
			log.Fatalf("bad argument %q (want label=<id>,<image id>,<image>)", arg)
		}
		api := only{Client: c, list: []docker.Container{{ID: parts[0], ImageID: parts[1], Image: parts[2]}}}
		col := &containers.Collector{API: api, Logf: log.Printf}
		r, err := col.Collect(ctx)
		if err != nil {
			log.Fatal(err)
		}
		img := r.Images[0]
		text := fmt.Sprintf("status=%s\n%s", img.Status, img.Inventory)
		if err := os.WriteFile(filepath.Join(*out, label+".txt"), []byte(text), 0o644); err != nil {
			log.Fatal(err)
		}
	}
}
