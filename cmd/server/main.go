package main

import (
	"flag"
	"fmt"
	"log"
	"net/url"
	"os"
	"os/signal"
	"syscall"

	"github.com/jmoiron/sqlx"
	cfg "github.com/kabili207/mesh-mqtt-server/pkg/config"
	"github.com/kabili207/mesh-mqtt-server/pkg/hooks"
	"github.com/kabili207/mesh-mqtt-server/pkg/store"
	mqtt "github.com/mochi-mqtt/server/v2"
	"github.com/mochi-mqtt/server/v2/listeners"
	"github.com/spf13/viper"
)

var (
	config cfg.Configuration
)

func check(e error) {
	if e != nil {
		panic(e)
	}
}

func init() {

	configPath := flag.String("c", "config.yml", "The path to the config file")
	flag.Parse()
	f, err := os.Open(*configPath)
	check(err)
	viper.AutomaticEnv()
	viper.SetConfigType("yml")

	err = viper.ReadConfig(f)
	check(err)
	err = viper.Unmarshal(&config)
	//err = viper.Unmarshal(&config, viper.DecodeHook(DecodeForwardersFunc()))
	check(err)
}

func main() {

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

	server := mqtt.New(&mqtt.Options{
		InlineClient: true, // you must enable inline client to use direct publishing and subscribing.
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

	// Add custom hook (ExampleHook) to the server
	err = server.AddHook(new(hooks.MeshtasticHook), &hooks.MeshtasticHookOptions{
		Server:  server,
		Storage: storage,
	})

	if err != nil {
		log.Fatal(err)
	}

	// Start the server
	go func() {
		err := server.Serve()
		if err != nil {
			log.Fatal(err)
		}
	}()

	// Demonstration of directly publishing messages to a topic via the
	// `server.Publish` method. Subscribe to `direct/publish` using your
	// MQTT client to see the messages.
	//go func() {
	//	cl := server.NewClient(nil, "local", "inline", true)
	//	for range time.Tick(time.Second * 1) {
	//		err := server.InjectPacket(cl, packets.Packet{
	//			FixedHeader: packets.FixedHeader{
	//				Type: packets.Publish,
	//			},
	//			TopicName: "direct/publish",
	//			Payload:   []byte("injected scheduled message"),
	//		})
	//		if err != nil {
	//			server.Log.Error("server.InjectPacket", "error", err)
	//		}
	//		server.Log.Info("main.go injected packet to direct/publish")
	//	}
	//}()
	//
	//// There is also a shorthand convenience function, Publish, for easily sending
	//// publish packets if you are not concerned with creating your own packets.
	//go func() {
	//	for range time.Tick(time.Second * 5) {
	//		err := server.Publish("direct/publish", []byte("packet scheduled message"), false, 0)
	//		if err != nil {
	//			server.Log.Error("server.Publish", "error", err)
	//		}
	//		server.Log.Info("main.go issued direct message to direct/publish")
	//	}
	//}()

	<-done
	server.Log.Warn("caught signal, stopping...")
	_ = server.Close()
	server.Log.Info("main.go finished")
}

func setupDatabase(config cfg.Configuration) (*sqlx.DB, error) {
	// change "postgres" for whatever supported database you want to use
	dbUrl := url.URL{
		Scheme: "postgres",
		Host:   config.Database.Host,
		Path:   config.Database.DB,
		User:   url.UserPassword(config.Database.User, config.Database.Password),
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
