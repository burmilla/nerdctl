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

package main

import (
	"github.com/containerd/nerdctl/pkg/api/types"
	"github.com/spf13/cobra"

	"github.com/containerd/containerd"
	"github.com/containerd/containerd/defaults"
	ncdefaults "github.com/containerd/nerdctl/pkg/defaults"
)

func processRootCmdFlags(cmd *cobra.Command) (types.GlobalCommandOptions, error) {
	return types.GlobalCommandOptions{
		Debug:            false,
		DebugFull:        false,
		Address:          defaults.DefaultAddress,
		Namespace:        "burmillaos",
		Snapshotter:      containerd.DefaultSnapshotter,
		CNIPath:          ncdefaults.CNIPath(),
		CNINetConfPath:   ncdefaults.CNINetConfPath(),
		DataRoot:         ncdefaults.DataRoot(),
		CgroupManager:    ncdefaults.CgroupManager(),
		InsecureRegistry: false,
		HostsDir:         ncdefaults.HostsDirs(),
		Experimental:     true,
	}, nil
}
