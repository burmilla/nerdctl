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

package image

import (
	"context"
	"fmt"
	"io"

	"github.com/containerd/containerd"
	"github.com/containerd/nerdctl/pkg/api/types"
	"github.com/containerd/nerdctl/pkg/clientutil"
	"github.com/containerd/nerdctl/pkg/imgutil"
	"github.com/containerd/nerdctl/pkg/platformutil"
	"github.com/containerd/nerdctl/pkg/strutil"
	v1 "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/sirupsen/logrus"
)

func Pull(ctx context.Context, rawRef string, stdout io.Writer, stderr io.Writer, options types.PullCommandOptions) error {
	client, ctx, cancel, err := clientutil.NewClient(ctx, options.GOptions.Namespace, options.GOptions.Address)
	if err != nil {
		return err
	}
	defer cancel()

	ocispecPlatforms, err := platformutil.NewOCISpecPlatformSlice(options.AllPlatforms, options.Platform)
	if err != nil {
		return err
	}

	unpack, err := strutil.ParseBoolOrAuto(options.Unpack)
	if err != nil {
		return err
	}

	_, err = EnsureImage(ctx, client, rawRef, stdout, stderr, options, ocispecPlatforms, "always", unpack, options.Quiet)
	if err != nil {
		return err
	}

	return nil
}

func EnsureImage(ctx context.Context, client *containerd.Client, rawRef string, stdout io.Writer, stderr io.Writer, options types.PullCommandOptions, ocispecPlatforms []v1.Platform, pull string, unpack *bool, quiet bool) (*imgutil.EnsuredImage, error) {

	var ensured *imgutil.EnsuredImage

	ref := rawRef
	var err error
	switch options.Verify {
	case "none":
		logrus.Debugf("verification process skipped")
	default:
		return nil, fmt.Errorf("no verifier found: %s", options.Verify)
	}

	ensured, err = imgutil.EnsureImage(ctx, client, stdout, stderr, options.GOptions.Snapshotter, ref,
		pull, options.GOptions.InsecureRegistry, options.GOptions.HostsDir, ocispecPlatforms, unpack, quiet)
	if err != nil {
		return nil, err
	}
	return ensured, err
}
