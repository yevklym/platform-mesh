/*
Copyright The Platform Mesh Authors.

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

package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	"go.platform-mesh.io/security-operator/pkg/authz"

	ctrlruntimeclient "sigs.k8s.io/controller-runtime/pkg/client"
)

func init() {
	var kubeconfig, casesPath, output, profile, revision string
	command := &cobra.Command{Use: "authz-validate", SilenceUsage: true, Short: "Run headless API and access-review scenarios and write presentation evidence", RunE: func(cmd *cobra.Command, args []string) error {
		if profile != "authz-baseline" && profile != "authz-openfga" && profile != "authz-rbac" {
			return fmt.Errorf("invalid profile")
		}
		if revision == "" {
			return fmt.Errorf("--revision is required for reproducible evidence")
		}
		cfg, err := getKubeconfigFromPath(kubeconfig)
		if err != nil {
			return err
		}
		data, err := os.ReadFile(casesPath)
		if err != nil {
			return err
		}
		var cases []authz.ValidationCase
		if err := json.Unmarshal(data, &cases); err != nil {
			return err
		}
		if len(cases) == 0 {
			return fmt.Errorf("no scenarios")
		}
		report := authz.ValidationReport{Profile: profile, Revision: revision, Started: time.Now().UTC(), IdentityMode: "synthetic kcp impersonation; OIDC mapping untested"}
		factory := func(workspace string) (ctrlruntimeclient.Client, error) {
			return ctrlruntimeclient.New(authz.WorkspaceConfig(cfg, workspace), ctrlruntimeclient.Options{Scheme: scheme})
		}
		report.Results, err = authz.ValidateCases(cmd.Context(), cfg, factory, cases)
		if err != nil {
			return err
		}
		if err := authz.WriteReport(output, report); err != nil {
			return err
		}
		failed := 0
		for _, r := range report.Results {
			if r.Classification == "defect" {
				failed++
				fmt.Fprintf(cmd.ErrOrStderr(), "%s: %s\n", r.ID, r.Reason)
			}
		}
		if failed > 0 {
			return fmt.Errorf("%d validation checks failed; see %s/results.md", failed, output)
		}
		return nil
	}}
	f := command.Flags()
	f.StringVar(&kubeconfig, "kcp-kubeconfig", "", "administrator kubeconfig")
	f.StringVar(&casesPath, "cases", "", "scenario JSON file")
	f.StringVar(&output, "output", "contrib/poc/authz/results/latest", "evidence directory")
	f.StringVar(&profile, "profile", "", "tested composition")
	f.StringVar(&revision, "revision", "", "source revision including dirty marker when applicable")
	rootCmd.AddCommand(command)
}
