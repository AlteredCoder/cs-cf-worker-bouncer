package cmd

import (
	"bytes"
	"context"
	"crowdsec-cf-worker-bouncer/pkg/cf"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"crowdsec-cf-worker-bouncer/pkg/cfg"

	"github.com/crowdsecurity/crowdsec/pkg/apiclient"
	"github.com/crowdsecurity/crowdsec/pkg/models"
	csbouncer "github.com/crowdsecurity/go-cs-bouncer"
	"github.com/crowdsecurity/go-cs-lib/pkg/version"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"
)

const (
	DEFAULT_CONFIG_PATH = "/etc/crowdsec/bouncers/crowdsec-cloudflare-bouncer.yaml"
	name                = "crowdsec-cloudflare-bouncer"
)

func HandleSignals(ctx context.Context) error {
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, syscall.SIGTERM, syscall.SIGINT)

	select {
	case s := <-signalChan:
		switch s {
		case syscall.SIGTERM:
			return fmt.Errorf("received SIGTERM")
		case syscall.SIGINT:
			return fmt.Errorf("received SIGINT")
		}
	case <-ctx.Done():
		return ctx.Err()
	}
	return nil
}

func normalizeDecisions(decisions []*models.Decision) []*models.Decision {
	for i := range decisions {
		*decisions[i].Value = strings.ToLower(*decisions[i].Value)
		*decisions[i].Scope = strings.ToLower(*decisions[i].Scope)
		*decisions[i].Type = strings.ToLower(*decisions[i].Type)
	}
	return decisions
}

func getConfigFromPath(configPath string) (*cfg.BouncerConfig, error) {
	configBytes, err := cfg.MergedConfig(configPath)
	if err != nil {
		return nil, fmt.Errorf("unable to read config file: %w", err)
	}

	conf, err := cfg.NewConfig(bytes.NewReader(configBytes))
	if err != nil {
		return nil, fmt.Errorf("unable to parse config: %w", err)
	}
	return conf, nil
}

func CloudflareManagersFromConfig(ctx context.Context, accountConfigs []cfg.AccountConfig) ([]*cf.CloudflareAccountManager, error) {
	cfManagers := make([]*cf.CloudflareAccountManager, 0)
	for _, accountCfg := range accountConfigs {
		cfg := accountCfg
		manager, err := cf.NewCloudflareManager(ctx, cfg)
		if err != nil {
			return nil, fmt.Errorf("unable to create cloudflare manager: %w", err)
		}
		cfManagers = append(cfManagers, manager)
	}
	return cfManagers, nil
}

func Execute(configTokens *string, configOutputPath *string, configPath *string, ver *bool, testConfig *bool, showConfig *bool, deleteOnly *bool, setupOnly *bool) error {
	if ver != nil && *ver {
		fmt.Print(version.FullString())
		return nil
	}

	if configPath == nil || *configPath == "" {
		configPath = new(string)
		*configPath = DEFAULT_CONFIG_PATH
	}

	if configTokens != nil && *configTokens != "" {
		cfgTokenString, err := cfg.ConfigTokens(*configTokens, *configPath)
		if err != nil {
			return err
		}
		if configOutputPath != nil && *configOutputPath != "" {
			err := os.WriteFile(*configOutputPath, []byte(cfgTokenString), 0664)
			if err != nil {
				return err
			}
			log.Printf("Config successfully generated in %s", *configOutputPath)
		} else {
			fmt.Print(cfgTokenString)
		}
		return nil
	}

	conf, err := getConfigFromPath(*configPath)
	if err != nil {
		return err
	}
	if showConfig != nil && *showConfig {
		fmt.Printf("%+v", conf)
		return nil
	}

	csLAPI := &csbouncer.StreamBouncer{
		APIKey:         conf.CrowdSecLAPIKey,
		APIUrl:         conf.CrowdSecLAPIUrl,
		TickerInterval: conf.CrowdsecUpdateFrequencyYAML,
		UserAgent:      fmt.Sprintf("%s/%s", name, version.String()),
		Opts: apiclient.DecisionsStreamOpts{
			Scopes:                 "ip,range,as,country",
			ScenariosNotContaining: strings.Join(conf.ExcludeScenariosContaining, ","),
			ScenariosContaining:    strings.Join(conf.IncludeScenariosContaining, ","),
			Origins:                strings.Join(conf.OnlyIncludeDecisionsFrom, ","),
		},
		CertPath: conf.CertPath,
		KeyPath:  conf.KeyPath,
		CAPath:   conf.CAPath,
	}

	if (testConfig != nil && *testConfig) || (setupOnly == nil || (setupOnly != nil && !*setupOnly)) || (deleteOnly == nil || (deleteOnly != nil && !*deleteOnly)) {
		if err := csLAPI.Init(); err != nil {
			return fmt.Errorf("unable to initialize crowdsec bouncer: %w", err)
		}
	}

	if testConfig != nil && *testConfig {
		log.Info("config is valid")
		return nil
	}

	rootCtx := context.Background()
	g, ctx := errgroup.WithContext(rootCtx)
	cfManagers, err := CloudflareManagersFromConfig(ctx, conf.CloudflareConfig.Accounts)
	if err != nil {
		return err
	}
	for _, cfManager := range cfManagers {
		manager := cfManager
		g.Go(func() error {
			err := manager.CleanUpExistingWorkers()
			if err != nil {
				return fmt.Errorf("unable to cleanup existing workers: %w for account %s", err, manager.AccountCfg.OwnerEmail)
			}
			if deleteOnly != nil && *deleteOnly {
				return nil
			}
			if err := manager.DeployInfra(); err != nil {
				return fmt.Errorf("unable to deploy infra: %w for account %s", err, manager.AccountCfg.OwnerEmail)
			}
			log.Infof("Successfully deployed infra for account %s", manager.AccountCfg.OwnerEmail)
			return nil
		})
	}
	if err := g.Wait(); err != nil {
		return err
	}
	if deleteOnly != nil && *deleteOnly {
		return nil
	}
	log.Info("Successfully deployed infra for all accounts")
	if setupOnly != nil && *setupOnly {
		return nil
	}

	g, ctx = errgroup.WithContext(context.Background())
	for i, manager := range cfManagers {
		cfManagers[i].Ctx = ctx
		m := manager
		g.Go(func() error {
			if err := m.HandleTurnstile(); err != nil {
				return fmt.Errorf("unable to handle turnstile: %w", err)
			}
			return nil
		})
	}

	g.Go(func() error {
		return HandleSignals(ctx)
	})

	g.Go(func() error {
		csLAPI.Run(ctx)
		return fmt.Errorf("crowdsec bouncer stopped")
	})

	if conf.PrometheusConfig.Enabled {
		prometheus.MustRegister(csbouncer.TotalLAPICalls, csbouncer.TotalLAPIError, cf.CloudflareAPICallsByAccount)
		g.Go(func() error {
			http.Handle("/metrics", promhttp.Handler())
			return http.ListenAndServe(net.JoinHostPort(conf.PrometheusConfig.ListenAddress, conf.PrometheusConfig.ListenPort), nil)
		})
	}
	for {
		select {
		case <-ctx.Done():
			log.Warnf("context done: %s", ctx.Err())
			return ctx.Err()
		case streamDecision := <-csLAPI.Stream:
			if streamDecision == nil {
				return fmt.Errorf("stream decision is nil")
			}
			streamDecision.Deleted = normalizeDecisions(streamDecision.Deleted)
			streamDecision.New = normalizeDecisions(streamDecision.New)
			if len(streamDecision.Deleted) > 0 {
				log.Infof("Received %d deleted decisions", len(streamDecision.Deleted))
			}
			if len(streamDecision.New) > 0 {
				log.Infof("Received %d new decisions", len(streamDecision.New))
			}
			mg := errgroup.Group{}
			for _, m := range cfManagers {
				manager := m
				mg.Go(func() error {
					if err := manager.ProcessDeletedDecisions(streamDecision.Deleted); err != nil {
						return fmt.Errorf("unable to process deleted decisions: %w", err)
					}
					if err := manager.ProcessNewDecisions(streamDecision.New); err != nil {
						return fmt.Errorf("unable to process new decisions: %w", err)
					}
					return nil
				})
			}
			if err := mg.Wait(); err != nil {
				return err
			}
		}
	}
}
