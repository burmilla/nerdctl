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

	"github.com/containerd/nerdctl/pkg/api/types"
	"github.com/containerd/nerdctl/pkg/cmd/container"

	"github.com/spf13/cobra"
)

func newContainerInspectCommand() *cobra.Command {
	var containerInspectCommand = &cobra.Command{
		Use:               "inspect [flags] CONTAINER [CONTAINER, ...]",
		Short:             "Display detailed information on one or more containers.",
		Long:              "Hint: set `--mode=native` for showing the full output",
		Args:              cobra.MinimumNArgs(1),
		RunE:              containerInspectAction,
		ValidArgsFunction: containerInspectShellComplete,
		SilenceUsage:      true,
		SilenceErrors:     true,
	}
	containerInspectCommand.Flags().String("mode", "dockercompat", `Inspect mode, "dockercompat" for Docker-compatible output, "native" for containerd-native output`)
	containerInspectCommand.Flags().StringP("format", "f", "", "Format the output using the given Go template, e.g, '{{json .}}'")
	return containerInspectCommand
}

var validModeType = map[string]bool{
	"native":       true,
	"dockercompat": true,
}

func containerInspectAction(cmd *cobra.Command, args []string) error {
	globalOptions, err := processRootCmdFlags(cmd)
	if err != nil {
		return err
	}
	mode, err := cmd.Flags().GetString("mode")
	if err != nil {
		return err
	}
	if len(mode) > 0 && !validModeType[mode] {
		return fmt.Errorf("%q is not a valid value for --mode", mode)
	}
	format, err := cmd.Flags().GetString("format")
	if err != nil {
		return err
	}
	return container.Inspect(cmd.Context(), types.ContainerInspectCommandOptions{
		GOptions:   globalOptions,
		Format:     format,
		Mode:       mode,
		Containers: args,
	}, cmd.OutOrStdout())
}

func containerInspectShellComplete(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	return []string{""}, 0
}
