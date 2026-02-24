package main

import (
	"flag"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"os/signal"
	"syscall"

	"github.com/go-viper/mapstructure/v2"
	"github.com/jmoiron/sqlx"
	sloghelper "github.com/kabili207/slog-helper"
	"github.com/kabili207/mesh-mqtt-server/pkg/auth"
	cfg "github.com/kabili207/mesh-mqtt-server/pkg/config"
	"github.com/kabili207/mesh-mqtt-server/pkg/discord"
	"github.com/kabili207/mesh-mqtt-server/pkg/hooks"
	"github.com/kabili207/mesh-mqtt-server/pkg/meshsense"
	"github.com/kabili207/mesh-mqtt-server/pkg/routes"
	"github.com/kabili207/mesh-mqtt-server/pkg/store"
	mqtt "github.com/mochi-mqtt/server/v2"
	"github.com/mochi-mqtt/server/v2/listeners"
	"github.com/spf13/viper"
)

func main() {
	sloghelper.InitFromEnv()

	if err := run(); err != nil {
		slog.Error("Fatal error", "error", err)
		os.Exit(1)
	}
}

func run() error {
	config, err := loadConfig()
	if err != nil {
		return err
	}

	sloghelper.InitFromConfig(config.LogLevel, config.LogFormat, "")

	// Generate hash and salt
	hash, salt := auth.GenerateHashAndSalt("YhyxnE4QPUGZ7^oGJ@zb")
	fmt.Printf("Hash: %s\nSalt%s\n", hash, salt)

	database, err := setupDatabase(*config)
	if err != nil {
		return fmt.Errorf("error connecting to database: %w", err)
	}

	storage, err := store.New(database)
	if err != nil {
		return fmt.Errorf("error initializing storage: %w", err)
	}

	err = storage.RunMigrations()
	if err != nil {
		return fmt.Errorf("error running migrations: %w", err)
	}

	sigs := make(chan os.Signal, 1)
	done := make(chan bool, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigs
		done <- true
	}()

	caps := mqtt.NewDefaultServerCapabilities()
	caps.MaximumSessionExpiryInterval = 3600 // 1 hour - accommodate mobile devices with intermittent connectivity
	caps.MaximumMessageExpiryInterval = 3600 // 1 hour
	caps.ReceiveMaximum = 1000               // Max in-flight messages
	caps.MaximumPacketSize = 2048            // 2KB - well above the ~256 byte mesh RF limit, accounts for MQTT overhead
	caps.MaximumClientWritesPending = 1024   // Pending outbound messages
	server := mqtt.New(&mqtt.Options{
		InlineClient: true, // you must enable inline client to use direct publishing and subscribing.
		Logger:       slog.Default(),
		Capabilities: caps,
	})

	//_ = server.AddHook(new(auth.AllowHook), nil)
	tcp := listeners.NewTCP(listeners.Config{
		ID:      "t1",
		Address: ":1883",
	})

	err = server.AddListener(tcp)
	if err != nil {
		return fmt.Errorf("error adding TCP listener: %w", err)
	}

	// Create router and client notifier first
	router := &routes.WebRouter{}
	clientNotifier := routes.NewClientNotifier()
	router.ClientNotifier = clientNotifier

	// Add auth hook first — handles authentication, ACL, and client lifecycle
	authHook := new(hooks.AuthHook)
	err = server.AddHook(authHook, &hooks.AuthHookOptions{
		Server:         server,
		Storage:        storage,
		ClientNotifier: clientNotifier,
	})
	if err != nil {
		return fmt.Errorf("error adding auth hook: %w", err)
	}

	router.MqttServer = authHook

	// Create MeshSense client if enabled
	var meshSenseClient *meshsense.Client
	if config.MeshSense.Enabled {
		meshSenseClient = meshsense.NewClient(
			config.MeshSense.URL,
			config.MeshSettings.SelfNode.NodeID,
			config.MeshSettings.SelfNode.ShortName,
		)
		url := config.MeshSense.URL
		if url == "" {
			url = meshsense.DefaultURL
		}
		slog.Info("MeshSense forwarding enabled", "url", url)
	}

	// Add Meshtastic protocol hook
	meshHook := new(hooks.MeshtasticHook)
	err = server.AddHook(meshHook, &hooks.MeshtasticHookOptions{
		Server:       server,
		Storage:      storage,
		MeshSettings: config.MeshSettings,
		AuthHook:     authHook,
		MeshSense:    meshSenseClient,
	})
	if err != nil {
		return fmt.Errorf("error adding meshtastic hook: %w", err)
	}

	// Register Meshtastic hook as enricher, ACL checker, and lifecycle listener
	authHook.RegisterClientEnricher(meshHook)
	authHook.RegisterACLChecker(meshHook)
	authHook.RegisterLifecycleListener(meshHook)

	// Add forwarding hook if enabled
	var forwardingHook *hooks.ForwardingHook
	if config.Forwarding.Enabled {
		forwardingHook = new(hooks.ForwardingHook)
		err = server.AddHook(forwardingHook, &hooks.ForwardingHookOptions{
			Settings: config.Forwarding,
		})
		if err != nil {
			return fmt.Errorf("error adding forwarding hook: %w", err)
		}
		router.ForwardingHook = forwardingHook
	}

	// Add MeshCore hook if enabled
	var meshCoreHook *hooks.MeshCoreHook
	if config.MeshCore.Enabled {
		meshCoreHook = new(hooks.MeshCoreHook)
		err = server.AddHook(meshCoreHook, &hooks.MeshCoreHookOptions{
			Server:   server,
			Storage:  storage,
			Settings: config.MeshCore,
			AuthHook: authHook,
		})
		if err != nil {
			return fmt.Errorf("error adding meshcore hook: %w", err)
		}
		authHook.RegisterClientEnricher(meshCoreHook)
		authHook.RegisterACLChecker(meshCoreHook)
	}

	// Add Bridge hook if enabled
	var bridgeHook *hooks.BridgeHook
	if config.Bridge.Enabled {
		bridgeHook = new(hooks.BridgeHook)
		err = server.AddHook(bridgeHook, &hooks.BridgeHookOptions{
			Server:       server,
			MeshSettings: config.MeshSettings,
			Bridge:       config.Bridge,
			Storage:      storage,
		})
		if err != nil {
			return fmt.Errorf("error adding bridge hook: %w", err)
		}
	}

	// Wire up cross-hook references
	if meshCoreHook != nil && bridgeHook != nil {
		meshCoreHook.SetBridgeHook(bridgeHook)
	}

	// Start the server
	go func() {
		err := server.Serve()
		if err != nil {
			slog.Error("MQTT server error", "error", err)
		}
	}()

	go func() {
		err := router.Initialize(*config, *storage)
		if err != nil {
			slog.Error("Web router error", "error", err)
		}
	}()

	// Start Discord admin role sync if configured
	roleSync := discord.NewRoleSync(config.Discord, *storage)
	if roleSync != nil {
		go roleSync.Start()
	}

	<-done
	slog.Warn("caught signal, stopping...")

	// Stop background tasks
	if roleSync != nil {
		roleSync.Stop()
	}

	// Stop hooks gracefully
	_ = authHook.Stop()
	_ = meshHook.Stop()
	if forwardingHook != nil {
		_ = forwardingHook.Stop()
	}
	if meshCoreHook != nil {
		_ = meshCoreHook.Stop()
	}
	if bridgeHook != nil {
		_ = bridgeHook.Stop()
	}

	_ = server.Close()
	slog.Info("main.go finished")
	return nil
}

func loadConfig() (*cfg.Configuration, error) {
	configPath := flag.String("c", "config.yml", "The path to the config file")
	flag.Parse()

	f, err := os.Open(*configPath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	viper.AutomaticEnv()
	viper.SetConfigType("yml")

	if err := viper.ReadConfig(f); err != nil {
		return nil, err
	}

	var config cfg.Configuration
	if err := viper.Unmarshal(&config, viper.DecodeHook(mapstructure.TextUnmarshallerHookFunc())); err != nil {
		return nil, err
	}
	return &config, nil
}

func setupDatabase(config cfg.Configuration) (*sqlx.DB, error) {
	// PgBouncer has problems with prepared statements in transaction mode
	// so we have to force binary_parameters
	// https://blog.bullgare.com/2019/06/pgbouncer-and-prepared-statements/
	opts := url.Values{}
	opts.Add("binary_parameters", "yes")

	dbUrl := url.URL{
		Scheme:   "postgres",
		Host:     config.Database.Host,
		Path:     config.Database.DB,
		User:     url.UserPassword(config.Database.User, config.Database.Password),
		RawQuery: opts.Encode(),
	}

	db, err := sqlx.Open("postgres", dbUrl.String())
	if err != nil {
		return nil, err
	}

	// ping the DB to ensure that it is connected
	err = db.Ping()
	if err != nil {
		return nil, err
	}

	return db, nil
}
