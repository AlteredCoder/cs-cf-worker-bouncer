package cf

import (
	"context"
	"crowdsec-cf-worker-bouncer/pkg/cfg"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	_ "embed"

	cf "github.com/cloudflare/cloudflare-go"
	"github.com/crowdsecurity/crowdsec/pkg/models"
	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"
)

var CloudflareAPICallsByAccount = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: "cloudflare_api_calls_total",
		Help: "Number of api calls made to cloudflare by each account",
	},
	[]string{"account"},
)

//go:embed worker/dist/main.js
var workerScript string

const (
	ScriptName                = "crowdsec-cloudflare-bouncer-worker"
	KVNsName                  = "CROWDSECCFBOUNCERNS"
	WidgetName                = "crowdsec-cloudflare-bouncer-widget"
	TurnstileConfigKey        = "TURNSTILE_CONFIG"
	VarNameForActionsByDomain = "ACTIONS_BY_DOMAIN"
	IpRangeKeyName            = "IP_RANGES"
)

type cloudflareAPI interface {
	Account(ctx context.Context, accountID string) (cf.Account, cf.ResultInfo, error)
	CreateTurnstileWidget(ctx context.Context, rc *cf.ResourceContainer, params cf.CreateTurnstileWidgetParams) (cf.TurnstileWidget, error)
	CreateWorkerRoute(ctx context.Context, rc *cf.ResourceContainer, params cf.CreateWorkerRouteParams) (cf.WorkerRouteResponse, error)
	CreateWorkersKVNamespace(ctx context.Context, rc *cf.ResourceContainer, params cf.CreateWorkersKVNamespaceParams) (cf.WorkersKVNamespaceResponse, error)
	DeleteTurnstileWidget(ctx context.Context, rc *cf.ResourceContainer, siteKey string) error
	DeleteWorker(ctx context.Context, rc *cf.ResourceContainer, params cf.DeleteWorkerParams) error
	DeleteWorkerRoute(ctx context.Context, rc *cf.ResourceContainer, routeID string) (cf.WorkerRouteResponse, error)
	DeleteWorkersKVEntries(ctx context.Context, rc *cf.ResourceContainer, params cf.DeleteWorkersKVEntriesParams) (cf.Response, error)
	DeleteWorkersKVNamespace(ctx context.Context, rc *cf.ResourceContainer, namespaceID string) (cf.Response, error)
	ListTurnstileWidgets(ctx context.Context, rc *cf.ResourceContainer, params cf.ListTurnstileWidgetParams) ([]cf.TurnstileWidget, *cf.ResultInfo, error)
	ListWorkerRoutes(ctx context.Context, rc *cf.ResourceContainer, params cf.ListWorkerRoutesParams) (cf.WorkerRoutesResponse, error)
	ListWorkersKVNamespaces(ctx context.Context, rc *cf.ResourceContainer, params cf.ListWorkersKVNamespacesParams) ([]cf.WorkersKVNamespace, *cf.ResultInfo, error)
	ListWorkersSecrets(ctx context.Context, rc *cf.ResourceContainer, params cf.ListWorkersSecretsParams) (cf.WorkersListSecretsResponse, error)
	ListZones(ctx context.Context, z ...string) ([]cf.Zone, error)
	RotateTurnstileWidget(ctx context.Context, rc *cf.ResourceContainer, param cf.RotateTurnstileWidgetParams) (cf.TurnstileWidget, error)
	SetWorkersSecret(ctx context.Context, rc *cf.ResourceContainer, params cf.SetWorkersSecretParams) (cf.WorkersPutSecretResponse, error)
	UploadWorker(ctx context.Context, rc *cf.ResourceContainer, params cf.CreateWorkerParams) (cf.WorkerScriptResponse, error)
	WriteWorkersKVEntries(ctx context.Context, rc *cf.ResourceContainer, params cf.WriteWorkersKVEntriesParams) (cf.Response, error)
}

type CloudflareAccountManager struct {
	AccountCfg            cfg.AccountConfig
	api                   cloudflareAPI
	Ctx                   context.Context
	logger                *log.Entry
	NamespaceID           string
	KVPairByDecisionValue map[string]cf.WorkersKVPair
	ipRangeKVPair         cf.WorkersKVPair
	ActionByIPRange       map[string]string
}

func NewCloudflareManager(ctx context.Context, accountCfg cfg.AccountConfig) (*CloudflareAccountManager, error) {
	api, err := NewCloudflareAPI(ctx, accountCfg)
	if err != nil {
		return nil, err
	}
	zones, err := api.ListZones(ctx)
	if err != nil {
		return nil, err
	}
	for i, zoneCfg := range accountCfg.ZoneConfigs {
		found := false
		for _, zone := range zones {
			if zone.ID == zoneCfg.ID {
				found = true
				accountCfg.ZoneConfigs[i].Domain = zone.Name
				break
			}
		}
		if !found {
			return nil, fmt.Errorf("zone %s not found in account %s", zoneCfg.ID, accountCfg.ID)
		}
	}
	return &CloudflareAccountManager{
		AccountCfg:      accountCfg,
		api:             api,
		Ctx:             ctx,
		logger:          log.WithFields(log.Fields{"account": accountCfg.OwnerEmail}),
		ipRangeKVPair:   cf.WorkersKVPair{Key: IpRangeKeyName, Value: "{}"},
		ActionByIPRange: make(map[string]string),
	}, nil
}

type CloudflareManagerHTTPTransport struct {
	http.Transport
	accountOwnerEmail string
}

func (cfT *CloudflareManagerHTTPTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	CloudflareAPICallsByAccount.WithLabelValues(cfT.accountOwnerEmail).Inc()
	return http.DefaultTransport.RoundTrip(req)
}

func NewCloudflareAPI(context context.Context, accountCfg cfg.AccountConfig) (cloudflareAPI, error) {
	transport := CloudflareManagerHTTPTransport{accountOwnerEmail: accountCfg.OwnerEmail}
	httpClient := http.Client{}
	httpClient.Transport = &transport
	api, err := cf.NewWithAPIToken(accountCfg.Token, cf.HTTPClient(&httpClient))
	if err != nil {
		return nil, err
	}
	return api, nil
}

type ActionsForZone struct {
	SupportedActions []string `json:"supported_actions"`
	DefaultAction    string   `json:"default_action"`
}

func (m *CloudflareAccountManager) DeployInfra() error {
	// Create the worker
	m.logger.Infof("Creating KVNS %s", KVNsName)
	kvNSResp, err := m.api.CreateWorkersKVNamespace(
		m.Ctx,
		cf.AccountIdentifier(m.AccountCfg.ID),
		cf.CreateWorkersKVNamespaceParams{Title: KVNsName},
	)
	if err != nil {
		return err
	}
	m.logger.Tracef("KVNS: %+v", kvNSResp)
	m.NamespaceID = kvNSResp.Result.ID

	actionsForZoneByDomain := make(map[string]ActionsForZone)
	for _, z := range m.AccountCfg.ZoneConfigs {
		actionsForZoneByDomain[z.Domain] = ActionsForZone{
			SupportedActions: z.Actions,
			DefaultAction:    z.DefaultAction,
		}
	}
	varActionsForZoneByDomain, err := json.Marshal(actionsForZoneByDomain)
	if err != nil {
		return err
	}

	m.logger.Infof("Creating worker %s", ScriptName)
	worker, err := m.api.UploadWorker(m.Ctx, cf.AccountIdentifier(m.AccountCfg.ID), cf.CreateWorkerParams{
		Script:     workerScript,
		ScriptName: ScriptName,
		Bindings: map[string]cf.WorkerBinding{
			KVNsName: cf.WorkerKvNamespaceBinding{NamespaceID: kvNSResp.Result.ID},
			VarNameForActionsByDomain: cf.WorkerPlainTextBinding{
				Text: string(varActionsForZoneByDomain),
			},
		},
		Module: true,
	})
	m.logger.Tracef("Worker: %+v", worker)

	if err != nil {
		return err
	}

	zg := errgroup.Group{}
	for _, z := range m.AccountCfg.ZoneConfigs {
		for _, r := range z.RoutesToProtect {
			zone := z
			route := r
			zoneLogger := m.logger.WithFields(log.Fields{"zone": zone.Domain})
			zoneLogger.Infof("Binding worker to route %s", route)
			zg.Go(func() error {
				workerRouteResp, err := m.api.CreateWorkerRoute(m.Ctx, cf.ZoneIdentifier(zone.ID), cf.CreateWorkerRouteParams{
					Pattern: route,
					Script:  worker.ID,
				})
				if err != nil {
					return err
				}
				zoneLogger.Tracef("WorkerRouteResp: %+v", workerRouteResp)
				zoneLogger.Infof("Binded worker to route %s", route)
				return nil
			})
		}
	}

	return zg.Wait()
}

func (m *CloudflareAccountManager) CleanUpExistingWorkers() error {
	m.logger.Infof("Cleaning up existing workers")

	m.logger.Debug("Listing existing turnstile widgets")
	widgets, _, err := m.api.ListTurnstileWidgets(m.Ctx, cf.AccountIdentifier(m.AccountCfg.ID), cf.ListTurnstileWidgetParams{})
	if err != nil {
		return err
	}
	m.logger.Tracef("widgets: %+v", widgets)
	m.logger.Debug("Done listing existing turnstile widgets")

	for _, widget := range widgets {
		if widget.Name == WidgetName {
			m.logger.Debugf("Deleting turnstile widget with site key %s", widget.SiteKey)
			if err := m.api.DeleteTurnstileWidget(m.Ctx, cf.AccountIdentifier(m.AccountCfg.ID), widget.SiteKey); err != nil {
				return err
			}
			m.logger.Debugf("Done deleting turnstile widget with site key %s", widget.SiteKey)
		}
	}
	m.logger.Debug("Done cleaning up existing turnstile widgets")

	for _, zone := range m.AccountCfg.ZoneConfigs {
		zoneLogger := m.logger.WithFields(log.Fields{"zone": zone.Domain})
		zoneLogger.Debugf("Listing worker routes")
		routeResp, err := m.api.ListWorkerRoutes(m.Ctx, cf.ZoneIdentifier(zone.ID), cf.ListWorkerRoutesParams{})
		if err != nil {
			return err
		}
		zoneLogger.Tracef("routeResp: %+v", routeResp)
		zoneLogger.Debugf("Done listing worker routes")

		for _, route := range routeResp.Routes {
			if route.ScriptName == ScriptName {
				zoneLogger.Debugf("Deleting worker route with ID %s", route.ID)
				_, err := m.api.DeleteWorkerRoute(m.Ctx, cf.ZoneIdentifier(zone.ID), route.ID)
				if err != nil {
					return err
				}
				zoneLogger.Debugf("Done deleting worker route with ID %s", route.ID)
			}
		}
	}

	m.logger.Debugf("Listing worker KV Namespaces")
	kvNamespaces, _, err := m.api.ListWorkersKVNamespaces(m.Ctx, cf.AccountIdentifier(m.AccountCfg.ID), cf.ListWorkersKVNamespacesParams{})
	if err != nil {
		return err
	}
	m.logger.Tracef("kvNamespaces: %+v", kvNamespaces)
	m.logger.Debugf("Done listing worker KV Namespaces")

	for _, kvNamespace := range kvNamespaces {
		if kvNamespace.Title == KVNsName {
			m.logger.Debugf("Deleting worker KV Namespace with ID %s", kvNamespace.ID)
			_, err := m.api.DeleteWorkersKVNamespace(m.Ctx, cf.AccountIdentifier(m.AccountCfg.ID), kvNamespace.ID)
			if err != nil {
				return err
			}
			m.logger.Debugf("Done deleting worker KV Namespace with ID %s", kvNamespace.ID)
		}
	}

	m.logger.Debugf("Attempting to delete worker script %s", ScriptName)
	err = m.api.DeleteWorker(m.Ctx, cf.AccountIdentifier(m.AccountCfg.ID), cf.DeleteWorkerParams{
		ScriptName: ScriptName,
	})
	if err != nil {
		if !strings.Contains(err.Error(), "workers.api.error.script_not_found") {
			return err
		}
		m.logger.Debugf("Didn't find worker script %s", ScriptName)
	} else {
		m.logger.Debugf("Deleted worker script %s", ScriptName)
	}
	m.logger.Info("Done cleaning up existing workers")
	return nil
}

func (m *CloudflareAccountManager) ProcessDeletedDecisions(decisions []*models.Decision) error {
	keysToDelete := make([]string, 0)
	newKVPairByValue := make(map[string]cf.WorkersKVPair)
	for _, kvPair := range m.KVPairByDecisionValue {
		newKVPairByValue[kvPair.Value] = kvPair
	}

	for _, decision := range decisions {
		if *decision.Scope == "range" {
			delete(m.ActionByIPRange, *decision.Value)
			continue
		}
		if val, ok := m.KVPairByDecisionValue[*decision.Value]; ok {
			if *decision.Type == val.Value {
				keysToDelete = append(keysToDelete, val.Key)
				delete(newKVPairByValue, val.Value)
			}
		}
	}
	if len(keysToDelete) == 0 {
		m.logger.Debug("No keys to delete")
		return nil
	}
	m.logger.Infof("Deleting %d keys", len(keysToDelete))
	for i := 0; i < len(keysToDelete); i += 10000 {
		begin := i
		end := min(i+10000, len(keysToDelete))
		resp, err := m.api.DeleteWorkersKVEntries(m.Ctx, cf.AccountIdentifier(m.AccountCfg.ID), cf.DeleteWorkersKVEntriesParams{
			Keys:        keysToDelete[begin:end],
			NamespaceID: m.NamespaceID,
		})
		if err != nil {
			return err
		}
		m.logger.Tracef("delete key resp: %+v", resp)
	}
	m.logger.Info("Done deleting keys")
	m.KVPairByDecisionValue = newKVPairByValue
	return m.CommitIPRangesIfChanged()
}

type WidgetTokenCfg struct {
	SiteKey string `json:"site_key"`
	Secret  string `json:"secret"`
}

func (m *CloudflareAccountManager) writeWidgetCfgToKV(ctx context.Context, widgetTokenCfgByDomain map[string]WidgetTokenCfg) error {
	turnstileConfig, err := json.Marshal(widgetTokenCfgByDomain)
	if err != nil {
		return err
	}
	kv := cf.WorkersKVPair{
		Key:   TurnstileConfigKey,
		Value: string(turnstileConfig),
	}
	m.logger.Infof("Writing turnstile cfg %+v", kv)
	resp, err := m.api.WriteWorkersKVEntries(ctx, cf.AccountIdentifier(m.AccountCfg.ID), cf.WriteWorkersKVEntriesParams{
		NamespaceID: m.NamespaceID,
		KVs:         []*cf.WorkersKVPair{&kv},
	})
	if err != nil {
		return err
	}
	m.logger.Tracef("resp after writing turnstile cfg %+v", resp)
	return nil
}

func (m *CloudflareAccountManager) ProcessNewDecisions(decisions []*models.Decision) error {
	keysToWrite := make([]*cf.WorkersKVPair, 0)
	newKVPairByValue := make(map[string]cf.WorkersKVPair)

	//copy existing kv pairs
	for _, kvPair := range m.KVPairByDecisionValue {
		newKVPairByValue[kvPair.Value] = kvPair
	}

	for _, decision := range decisions {
		if *decision.Scope == "range" {
			m.ActionByIPRange[*decision.Value] = *decision.Type
			continue
		}
		if val, ok := newKVPairByValue[*decision.Value]; ok {
			if *decision.Type != val.Value {
				keysToWrite = append(keysToWrite, &cf.WorkersKVPair{Key: *decision.Value, Value: *decision.Type})
				newKVPairByValue[*decision.Value] = cf.WorkersKVPair{Key: *decision.Value, Value: *decision.Type}
			}
		} else {
			keysToWrite = append(keysToWrite, &cf.WorkersKVPair{Key: *decision.Value, Value: *decision.Type})
			newKVPairByValue[*decision.Value] = cf.WorkersKVPair{Key: *decision.Value, Value: *decision.Type}
		}
	}
	if len(keysToWrite) == 0 {
		m.logger.Debug("No keys to write")
	} else {
		m.logger.Infof("Writing %d keys", len(keysToWrite))
		for i := 0; i < len(keysToWrite); i += 10000 {
			begin := i
			end := min(i+10000, len(keysToWrite))
			resp, err := m.api.WriteWorkersKVEntries(m.Ctx, cf.AccountIdentifier(m.AccountCfg.ID), cf.WriteWorkersKVEntriesParams{
				NamespaceID: m.NamespaceID,
				KVs:         keysToWrite[begin:end],
			})
			if err != nil {
				return err
			}
			m.logger.Tracef("write key resp: %+v", resp)
		}
		m.KVPairByDecisionValue = newKVPairByValue
	}

	return m.CommitIPRangesIfChanged()
}

func (m *CloudflareAccountManager) CommitIPRangesIfChanged() error {
	c, err := json.Marshal(m.ActionByIPRange)
	if err != nil {
		return err
	}
	ipRangeContent := string(c)
	if ipRangeContent != m.ipRangeKVPair.Value {
		m.logger.Debugf("IP ranges changed, writing new value: %s", ipRangeContent)
		m.ipRangeKVPair.Value = ipRangeContent
		_, err := m.api.WriteWorkersKVEntries(m.Ctx, cf.AccountIdentifier(m.AccountCfg.ID), cf.WriteWorkersKVEntriesParams{
			NamespaceID: m.NamespaceID,
			KVs:         []*cf.WorkersKVPair{&m.ipRangeKVPair},
		})
		if err != nil {
			return err
		}
	}
	return nil
}

func (m *CloudflareAccountManager) CreateTurnstileWidgets() (map[string]WidgetTokenCfg, error) {
	widgetCreatorGrp := errgroup.Group{}
	widgetTokenCfgByDomain := make(map[string]WidgetTokenCfg)
	widgetTokenCfgByDomainLock := sync.Mutex{}
	for _, z := range m.AccountCfg.ZoneConfigs {
		zone := z
		if !zone.Turnstile.Enabled {
			continue
		}
		zoneLogger := m.logger.WithFields(log.Fields{"zone": zone.Domain})
		zoneLogger.Info(("Creating turnstile widget"))
		widgetCreatorGrp.Go(func() error {
			resp, err := m.api.CreateTurnstileWidget(m.Ctx, cf.AccountIdentifier(m.AccountCfg.ID), cf.CreateTurnstileWidgetParams{
				Name:    WidgetName,
				Domains: []string{zone.Domain},
				Mode:    zone.Turnstile.Mode,
			})
			if err != nil {
				return err
			}
			zoneLogger.Tracef("resp: %+v", resp)
			zoneLogger.Info(("Done creating turnstile widget"))
			widgetTokenCfgByDomainLock.Lock()
			defer widgetTokenCfgByDomainLock.Unlock()
			widgetTokenCfgByDomain[zone.Domain] = WidgetTokenCfg{SiteKey: resp.SiteKey, Secret: resp.Secret}
			return nil
		})
	}
	if err := widgetCreatorGrp.Wait(); err != nil {
		return nil, err
	}
	return widgetTokenCfgByDomain, nil
}

func (m *CloudflareAccountManager) HandleTurnstile() error {
	widgetTokenCfgByDomainLock := sync.Mutex{}
	// Create the tokens
	widgetTokenCfgByDomain, err := m.CreateTurnstileWidgets()
	if err != nil {
		return err
	}

	if err := m.writeWidgetCfgToKV(m.Ctx, widgetTokenCfgByDomain); err != nil {
		return nil
	}

	// Start the rotators
	g, ctx := errgroup.WithContext(m.Ctx)
	for _, z := range m.AccountCfg.ZoneConfigs {
		if !z.Turnstile.RotateSecretKey || !z.Turnstile.Enabled {
			continue
		}
		zone := z
		g.Go(func() error {
			zoneLogger := m.logger.WithFields(log.Fields{"zone": zone.Domain})
			zoneLogger.Info(("Starting turnstile rotator"))
			ticker := time.NewTicker(zone.Turnstile.RotateSecretKeyEvery)
			for {
				select {
				case <-m.Ctx.Done():
					zoneLogger.Warn("Stopping turnstile rotator")
					return m.Ctx.Err()
				case <-ticker.C:
					zoneLogger.Info(("Rotating turnstile secret key"))
					widgetTokenCfgByDomainLock.Lock()
					widgetTokenCfg := widgetTokenCfgByDomain[zone.Domain]
					widgetTokenCfgByDomainLock.Unlock()
					resp, err := m.api.RotateTurnstileWidget(ctx, cf.AccountIdentifier(m.AccountCfg.ID), cf.RotateTurnstileWidgetParams{
						SiteKey:               widgetTokenCfg.SiteKey,
						InvalidateImmediately: true,
					})
					zoneLogger.Tracef("resp: %+v", resp)
					if err != nil {
						return err
					}
					widgetTokenCfg.Secret = resp.Secret
					widgetTokenCfgByDomainLock.Lock()
					widgetTokenCfgByDomain[zone.Domain] = widgetTokenCfg
					if err := m.writeWidgetCfgToKV(ctx, widgetTokenCfgByDomain); err != nil {
						return err
					}
					widgetTokenCfgByDomainLock.Unlock()
				}
			}
		})
	}
	return g.Wait()
}

func min(a, b int) int {
	if a > b {
		return b
	}
	return a
}
