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
	"fmt"
	"strings"

	"github.com/containerd/nerdctl/pkg/api/types"
	"github.com/containerd/nerdctl/pkg/clientutil"
	"github.com/containerd/nerdctl/pkg/cmd/volume"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

func newSystemPruneCommand() *cobra.Command {
	systemPruneCommand := &cobra.Command{
		Use:           "prune [flags]",
		Short:         "Remove unused data",
		Args:          cobra.NoArgs,
		RunE:          systemPruneAction,
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	systemPruneCommand.Flags().BoolP("all", "a", false, "Remove all unused images, not just dangling ones")
	systemPruneCommand.Flags().BoolP("force", "f", false, "Do not prompt for confirmation")
	systemPruneCommand.Flags().Bool("volumes", false, "Prune volumes")
	return systemPruneCommand
}

func systemPruneAction(cmd *cobra.Command, args []string) error {
	globalOptions, err := processRootCmdFlags(cmd)
	if err != nil {
		return err
	}
	all, err := cmd.Flags().GetBool("all")
	if err != nil {
		return err
	}

	if !all {
		logrus.Warn("Currently, `nerdctl system prune` requires --all to be specified. Skip pruning.")
		// NOP
		return nil
	}

	vFlag, err := cmd.Flags().GetBool("volumes")
	if err != nil {
		return err
	}

	force, err := cmd.Flags().GetBool("force")
	if err != nil {
		return err
	}

	if !force {
		var confirm string
		msg := `This will remove:
  - all stopped containers`
		if vFlag {
			msg += `
  - all volumes not used by at least one container`
		}
		msg += `
  - all images without at least one container associated to them
  - all build cache
`
		msg += "\nAre you sure you want to continue? [y/N] "
		fmt.Fprintf(cmd.OutOrStdout(), "WARNING! %s", msg)
		fmt.Fscanf(cmd.InOrStdin(), "%s", &confirm)

		if strings.ToLower(confirm) != "y" {
			return nil
		}
	}
	client, ctx, cancel, err := clientutil.NewClient(cmd.Context(), globalOptions.Namespace, globalOptions.Address)
	if err != nil {
		return err
	}
	defer cancel()

	if err := containerPrune(ctx, cmd, client, globalOptions); err != nil {
		return err
	}
	if vFlag {
		if err := volume.Prune(ctx, types.VolumePruneCommandOptions{
			GOptions: globalOptions,
			Force:    true,
		}, cmd.InOrStdin(), cmd.OutOrStdout()); err != nil {
			return err
		}
	}
	if err := imagePrune(ctx, cmd, client); err != nil {
		return nil
	}

	// TODO: print total reclaimed space

	return nil
}
