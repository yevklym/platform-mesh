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
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	fga "github.com/openfga/api/proto/openfga/v1"
	"github.com/spf13/cobra"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"go.platform-mesh.io/security-operator/pkg/authz"

	"k8s.io/client-go/rest"
	ctrl "sigs.k8s.io/controller-runtime"
	ctrlruntimeclient "sigs.k8s.io/controller-runtime/pkg/client"
)

func init() {
	var kubeconfig, backend, fgaAddr, storeName, cert, key, listen string
	var workspaces []string
	var interval time.Duration
	var checksOnly, projectionOnly bool
	command := &cobra.Command{Use: "authz", Short: "Experimental authorization intent reconciler", RunE: func(cmd *cobra.Command, args []string) error {
		if backend != "rbac" && backend != "openfga" {
			return fmt.Errorf("backend must be rbac or openfga")
		}
		if checksOnly && projectionOnly {
			return fmt.Errorf("checks-only and projection-only are mutually exclusive")
		}
		if checksOnly && backend != "openfga" {
			return fmt.Errorf("checks-only requires OpenFGA")
		}
		if len(workspaces) == 0 && !checksOnly {
			return fmt.Errorf("at least one --workspace is required")
		}
		if interval <= 0 {
			return fmt.Errorf("poll interval must be positive")
		}
		cfg, err := getKubeconfigFromPath(kubeconfig)
		if err != nil {
			return err
		}
		base, err := url.Parse(cfg.Host)
		if err != nil {
			return err
		}
		base.Path = strings.Split(base.Path, "/clusters/")[0]
		clients := func(workspace string) (ctrlruntimeclient.Client, error) {
			copy := rest.CopyConfig(cfg)
			u := *base
			u.Path += "/clusters/" + workspace
			copy.Host = u.String()
			return ctrlruntimeclient.New(copy, ctrlruntimeclient.Options{Scheme: scheme})
		}
		ctx := ctrl.SetupSignalHandler()
		reconciler := &authz.Reconciler{ClientFor: clients, Backend: backend}
		var server *http.Server
		serverErrors := make(chan error, 2)
		if backend == "openfga" {
			if !projectionOnly && (cert == "" || key == "") {
				return fmt.Errorf("OpenFGA mode requires --tls-cert and --tls-key")
			}
			conn, err := grpc.NewClient(fgaAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
			if err != nil {
				return err
			}
			defer func() { _ = conn.Close() }()
			if checksOnly {
				reconciler.FGA, err = authz.LoadFGA(ctx, fga.NewOpenFGAServiceClient(conn), storeName)
			} else {
				reconciler.FGA, err = authz.NewFGA(ctx, fga.NewOpenFGAServiceClient(conn), storeName)
			}
			if err != nil {
				return err
			}
			if !projectionOnly {
				server = &http.Server{Addr: listen, Handler: reconciler.FGA.Handler(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second}
				go func() { serverErrors <- server.ListenAndServeTLS(cert, key) }()
				defer func() {
					shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
					defer cancel()
					_ = server.Shutdown(shutdown)
				}()
			}
		}
		health := &authz.Health{}
		healthServer := &http.Server{Addr: defaultCfg.HealthProbeBindAddress, Handler: health.Handler(), ReadHeaderTimeout: 5 * time.Second}
		go func() { serverErrors <- healthServer.ListenAndServe() }()
		health.SetReady(true)
		defer func() {
			health.SetReady(false)
			shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = healthServer.Shutdown(shutdown)
		}()
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			for _, workspace := range workspaces {
				if checksOnly {
					break
				}
				attempt, cancel := context.WithTimeout(ctx, 5*time.Second)
				err := reconciler.Once(attempt, workspace)
				cancel()
				if err != nil {
					log.Error().Str("workspace", workspace).Err(err).Msg("authorization intent reconciliation pending")
				}
			}
			select {
			case <-ctx.Done():
				return nil
			case err := <-serverErrors:
				if !errors.Is(err, http.ErrServerClosed) {
					return err
				}
				return nil
			case <-ticker.C:
			}
		}
	}}
	f := command.Flags()
	f.StringVar(&kubeconfig, "kcp-kubeconfig", "", "administrator kcp kubeconfig")
	f.StringVar(&backend, "backend", "rbac", "rbac or openfga")
	f.StringSliceVar(&workspaces, "workspace", nil, "parent workspaces containing AuthorizationGrants")
	f.DurationVar(&interval, "poll-interval", time.Second, "reconciliation interval")
	f.StringVar(&fgaAddr, "fga-target", "localhost:8081", "PoC OpenFGA gRPC address")
	f.StringVar(&storeName, "store-name", "platform-mesh-authz-poc", "dedicated experimental store")
	f.StringVar(&listen, "listen", ":9444", "PoC webhook address")
	f.StringVar(&cert, "tls-cert", "", "webhook TLS certificate")
	f.StringVar(&key, "tls-key", "", "webhook TLS key")
	f.BoolVar(&checksOnly, "checks-only", false, "Serve checks using an existing store; do not project intent")
	f.BoolVar(&projectionOnly, "projection-only", false, "Project intent without serving authorization checks")
	rootCmd.AddCommand(command)
}
