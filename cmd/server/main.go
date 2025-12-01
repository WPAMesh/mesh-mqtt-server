package main

import (
	"flag"
	"fmt"
	"log"
	"log/slog"
	"net/url"
	"os"
	"os/signal"
	"syscall"

	"github.com/go-viper/mapstructure/v2"
	"github.com/jmoiron/sqlx"
	"github.com/kabili207/mesh-mqtt-server/pkg/auth"
	cfg "github.com/kabili207/mesh-mqtt-server/pkg/config"
	"github.com/kabili207/mesh-mqtt-server/pkg/hooks"
	"github.com/kabili207/mesh-mqtt-server/pkg/routes"
	"github.com/kabili207/mesh-mqtt-server/pkg/store"
	mqtt "github.com/mochi-mqtt/server/v2"
	"github.com/mochi-mqtt/server/v2/listeners"
	"github.com/spf13/viper"

	"github.com/MatusOllah/slogcolor"
)

var (
	config cfg.Configuration
	logger *slog.Logger
)

func check(e error) {
	if e != nil {
		panic(e)
	}
}

func init() {
	logLevel := slog.LevelInfo
	if os.Getenv("DEBUG") != "" {
		logLevel = slog.LevelDebug
	}
	opts := slogcolor.DefaultOptions
	opts.Level = logLevel
	logger = slog.New(slogcolor.NewHandler(os.Stdout, opts))
	slog.SetDefault(logger)

	configPath := flag.String("c", "config.yml", "The path to the config file")
	flag.Parse()
	f, err := os.Open(*configPath)
	check(err)
	viper.AutomaticEnv()
	viper.SetConfigType("yml")

	err = viper.ReadConfig(f)
	check(err)
	err = viper.Unmarshal(&config, viper.DecodeHook(mapstructure.TextUnmarshallerHookFunc()))
	check(err)
}

func main() {

	// Generate hash and salt
	hash, salt := auth.GenerateHashAndSalt("YhyxnE4QPUGZ7^oGJ@zb")
	fmt.Printf("Hash: %s\nSalt%s\n", hash, salt)

	database, err := setupDatabase(config)
	if err != nil {
		fmt.Println("error connecting to database,", err)
		return
	}

	storage, err := store.New(database)
	if err != nil {
		fmt.Println("error initializing storage,", err)
		return
	}

	err = storage.RunMigrations()
	if err != nil {
		fmt.Println("error running migrations,", err)
		return
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
		Logger:       logger,
		Capabilities: caps,
	})

	//_ = server.AddHook(new(auth.AllowHook), nil)
	tcp := listeners.NewTCP(listeners.Config{
		ID:      "t1",
		Address: ":1883",
	})

	err = server.AddListener(tcp)
	if err != nil {
		log.Fatal(err)
	}

	// Create router and client notifier first
	router := &routes.WebRouter{}
	clientNotifier := routes.NewClientNotifier()
	router.ClientNotifier = clientNotifier

	// Add custom hook (MeshtasticHook) to the server
	meshHook := new(hooks.MeshtasticHook)

	err = server.AddHook(meshHook, &hooks.MeshtasticHookOptions{
		Server:         server,
		Storage:        storage,
		MeshSettings:   config.MeshSettings,
		ClientNotifier: clientNotifier,
	})

	if err != nil {
		log.Fatal(err)
	}

	// Set the MQTT server on the router
	router.MqttServer = meshHook

	// Add forwarding hook if enabled
	var forwardingHook *hooks.ForwardingHook
	if config.Forwarding.Enabled {
		forwardingHook = new(hooks.ForwardingHook)
		err = server.AddHook(forwardingHook, &hooks.ForwardingHookOptions{
			Settings: config.Forwarding,
		})
		if err != nil {
			log.Fatal(err)
		}
		router.ForwardingHook = forwardingHook
	}

	// Start the server
	go func() {
		err := server.Serve()
		if err != nil {
			log.Fatal(err)
		}
	}()

	go func() {
		err := router.Initialize(config, *storage)
		if err != nil {
			log.Fatal(err)
		}
	}()

	<-done
	server.Log.Warn("caught signal, stopping...")

	// Stop forwarding hook gracefully
	if forwardingHook != nil {
		_ = forwardingHook.Stop()
	}

	_ = server.Close()
	server.Log.Info("main.go finished")
}

func setupDatabase(config cfg.Configuration) (*sqlx.DB, error) {
	// change "postgres" for whatever supported database you want to use

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
