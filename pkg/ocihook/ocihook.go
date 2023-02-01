/*
   Copyright The containerd Authors.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

package ocihook

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/containerd/containerd/cmd/ctr/commands"
	gocni "github.com/containerd/go-cni"
	"github.com/containerd/nerdctl/pkg/dnsutil/hostsstore"
	"github.com/containerd/nerdctl/pkg/labels"
	"github.com/containerd/nerdctl/pkg/netutil"
	"github.com/containerd/nerdctl/pkg/netutil/nettype"
	types100 "github.com/containernetworking/cni/pkg/types/100"
	"github.com/opencontainers/runtime-spec/specs-go"

	b4nndclient "github.com/rootless-containers/bypass4netns/pkg/api/daemon/client"
	rlkclient "github.com/rootless-containers/rootlesskit/pkg/api/client"
	"github.com/sirupsen/logrus"
)

const (
	// NetworkNamespace is the network namespace path to be passed to the CNI plugins.
	// When this annotation is set from the runtime spec.State payload, it takes
	// precedence over the PID based resolution (/proc/<pid>/ns/net) where pid is
	// spec.State.Pid.
	// This is mostly used for VM based runtime, where the spec.State PID does not
	// necessarily lives in the created container networking namespace.
	NetworkNamespace = labels.Prefix + "network-namespace"
)

func Run(stdin io.Reader, stderr io.Writer, event, dataStore, cniPath, cniNetconfPath string) error {
	if stdin == nil || event == "" || dataStore == "" || cniPath == "" || cniNetconfPath == "" {
		return errors.New("got insufficient args")
	}

	var state specs.State
	if err := json.NewDecoder(stdin).Decode(&state); err != nil {
		return err
	}

	containerStateDir := state.Annotations[labels.StateDir]
	if containerStateDir == "" {
		return errors.New("state dir must be set")
	}
	if err := os.MkdirAll(containerStateDir, 0700); err != nil {
		return fmt.Errorf("failed to create %q: %w", containerStateDir, err)
	}
	logFilePath := filepath.Join(containerStateDir, "oci-hook."+event+".log")
	logFile, err := os.Create(logFilePath)
	if err != nil {
		return err
	}
	defer logFile.Close()
	logrus.SetOutput(io.MultiWriter(stderr, logFile))

	opts, err := newHandlerOpts(&state, dataStore, cniPath, cniNetconfPath)
	if err != nil {
		return err
	}

	switch event {
	case "createRuntime":
		return onCreateRuntime(opts)
	case "postStop":
		return onPostStop(opts)
	default:
		return fmt.Errorf("unexpected event %q", event)
	}
}

func newHandlerOpts(state *specs.State, dataStore, cniPath, cniNetconfPath string) (*handlerOpts, error) {
	o := &handlerOpts{
		state:     state,
		dataStore: dataStore,
	}

	extraHosts, err := getExtraHosts(state)
	if err != nil {
		return nil, err
	}
	o.extraHosts = extraHosts

	hs, err := loadSpec(o.state.Bundle)
	if err != nil {
		return nil, err
	}
	o.rootfs = hs.Root.Path
	if !filepath.IsAbs(o.rootfs) {
		o.rootfs = filepath.Join(o.state.Bundle, o.rootfs)
	}

	namespace := o.state.Annotations[labels.Namespace]
	if namespace == "" {
		return nil, errors.New("namespace must be set")
	}
	if o.state.ID == "" {
		return nil, errors.New("state.ID must be set")
	}
	o.fullID = namespace + "-" + o.state.ID

	networksJSON := o.state.Annotations[labels.Networks]
	var networks []string
	if err := json.Unmarshal([]byte(networksJSON), &networks); err != nil {
		return nil, err
	}

	// System containers does not need network
	netType := nettype.None

	switch netType {
	case nettype.Host, nettype.None, nettype.Container:
		// NOP
	case nettype.CNI:
		e, err := netutil.NewCNIEnv(cniPath, cniNetconfPath, netutil.WithDefaultNetwork())
		if err != nil {
			return nil, err
		}
		cniOpts := []gocni.Opt{
			gocni.WithPluginDir([]string{cniPath}),
		}
		netMap, err := e.NetworkMap()
		if err != nil {
			return nil, err
		}
		for _, netstr := range networks {
			net, ok := netMap[netstr]
			if !ok {
				return nil, fmt.Errorf("no such network: %q", netstr)
			}
			cniOpts = append(cniOpts, gocni.WithConfListBytes(net.Bytes))
			o.cniNames = append(o.cniNames, netstr)
		}
		o.cni, err = gocni.New(cniOpts...)
		if err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("unexpected network type %v", netType)
	}

	if pidFile := o.state.Annotations[labels.PIDFile]; pidFile != "" {
		if err := commands.WritePidFile(pidFile, state.Pid); err != nil {
			return nil, err
		}
	}

	if portsJSON := o.state.Annotations[labels.Ports]; portsJSON != "" {
		if err := json.Unmarshal([]byte(portsJSON), &o.ports); err != nil {
			return nil, err
		}
	}

	if ipAddress, ok := o.state.Annotations[labels.IPAddress]; ok {
		o.containerIP = ipAddress
	}

	if macAddress, ok := o.state.Annotations[labels.MACAddress]; ok {
		o.contianerMAC = macAddress
	}

	return o, nil
}

type handlerOpts struct {
	state             *specs.State
	dataStore         string
	rootfs            string
	ports             []gocni.PortMapping
	cni               gocni.CNI
	cniNames          []string
	fullID            string
	rootlessKitClient rlkclient.Client
	bypassClient      b4nndclient.Client
	extraHosts        map[string]string // host:ip
	containerIP       string
	contianerMAC      string
}

// hookSpec is from https://github.com/containerd/containerd/blob/v1.4.3/cmd/containerd/command/oci-hook.go#L59-L64
type hookSpec struct {
	Root struct {
		Path string `json:"path"`
	} `json:"root"`
}

// loadSpec is from https://github.com/containerd/containerd/blob/v1.4.3/cmd/containerd/command/oci-hook.go#L65-L76
func loadSpec(bundle string) (*hookSpec, error) {
	f, err := os.Open(filepath.Join(bundle, "config.json"))
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var s hookSpec
	if err := json.NewDecoder(f).Decode(&s); err != nil {
		return nil, err
	}
	return &s, nil
}

func getExtraHosts(state *specs.State) (map[string]string, error) {
	extraHostsJSON := state.Annotations[labels.ExtraHosts]
	var extraHosts []string
	if err := json.Unmarshal([]byte(extraHostsJSON), &extraHosts); err != nil {
		return nil, err
	}

	hosts := make(map[string]string)
	for _, host := range extraHosts {
		if v := strings.SplitN(host, ":", 2); len(v) == 2 {
			hosts[v[0]] = v[1]
		}
	}
	return hosts, nil
}

func getNetNSPath(state *specs.State) (string, error) {
	// If we have a network-namespace annotation we use it over the passed Pid.
	netNsPath, netNsFound := state.Annotations[NetworkNamespace]
	if netNsFound {
		if _, err := os.Stat(netNsPath); err != nil {
			return "", err
		}

		return netNsPath, nil
	}

	if state.Pid == 0 && !netNsFound {
		return "", errors.New("both state.Pid and the netNs annotation are unset")
	}

	// We dont't have a networking namespace annotation, but we have a PID.
	s := fmt.Sprintf("/proc/%d/ns/net", state.Pid)
	if _, err := os.Stat(s); err != nil {
		return "", err
	}
	return s, nil
}

func getMACAddressOpts(opts *handlerOpts) ([]gocni.NamespaceOpts, error) {
	if opts.contianerMAC != "" {
		return []gocni.NamespaceOpts{
			gocni.WithLabels(map[string]string{
				// allow loose CNI argument verification
				// FYI: https://github.com/containernetworking/cni/issues/560
				"IgnoreUnknown": "1",
			}),
			gocni.WithArgs("MAC", opts.contianerMAC),
		}, nil
	}
	return nil, nil
}

func onCreateRuntime(opts *handlerOpts) error {

	if opts.cni != nil {
		nsPath, err := getNetNSPath(opts.state)
		if err != nil {
			return err
		}
		ctx := context.Background()
		hs, err := hostsstore.NewStore(opts.dataStore)
		if err != nil {
			return err
		}
		macAddressOpts, err := getMACAddressOpts(opts)
		if err != nil {
			return err
		}
		var namespaceOpts []gocni.NamespaceOpts
		namespaceOpts = append(namespaceOpts, macAddressOpts...)
		hsMeta := hostsstore.Meta{
			Namespace:  opts.state.Annotations[labels.Namespace],
			ID:         opts.state.ID,
			Networks:   make(map[string]*types100.Result, len(opts.cniNames)),
			Hostname:   opts.state.Annotations[labels.Hostname],
			ExtraHosts: opts.extraHosts,
			Name:       opts.state.Annotations[labels.Name],
		}
		cniRes, err := opts.cni.Setup(ctx, opts.fullID, nsPath, namespaceOpts...)
		if err != nil {
			return fmt.Errorf("failed to call cni.Setup: %w", err)
		}
		cniResRaw := cniRes.Raw()
		for i, cniName := range opts.cniNames {
			hsMeta.Networks[cniName] = cniResRaw[i]
		}

		if err := hs.Acquire(hsMeta); err != nil {
			return err
		}

	}
	return nil
}

func onPostStop(opts *handlerOpts) error {
	ctx := context.Background()
	if opts.cni != nil {
		var err error
		macAddressOpts, err := getMACAddressOpts(opts)
		if err != nil {
			return err
		}
		var namespaceOpts []gocni.NamespaceOpts
		namespaceOpts = append(namespaceOpts, macAddressOpts...)
		if err := opts.cni.Remove(ctx, opts.fullID, "", namespaceOpts...); err != nil {
			logrus.WithError(err).Errorf("failed to call cni.Remove")
			return err
		}
		hs, err := hostsstore.NewStore(opts.dataStore)
		if err != nil {
			return err
		}
		ns := opts.state.Annotations[labels.Namespace]
		if err := hs.Release(ns, opts.state.ID); err != nil {
			return err
		}
	}
	return nil
}
