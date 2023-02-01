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
	ncdefaults "github.com/containerd/nerdctl/pkg/defaults"
	"github.com/spf13/cobra"
)

func shellCompleteCgroupManagerNames(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	candidates := []string{"cgroupfs"}
	if ncdefaults.IsSystemdAvailable() {
		candidates = append(candidates, "systemd")
	}
	return candidates, cobra.ShellCompDirectiveNoFileComp
}
