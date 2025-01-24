package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"runtime/debug"
	"syscall"
	"time"

	"github.com/funglee2k22/qpep/client"
	"github.com/funglee2k22/qpep/server"
	"github.com/funglee2k22/qpep/shared"
	"github.com/funglee2k22/qpep/windivert"
)

func main() {
	defer func() {
		if err := recover(); err != nil {
			log.Printf("PANIC: %v", err)
			debug.PrintStack()
		}
	}()

	log.SetFlags(log.Ltime | log.Lmicroseconds)

	client.ClientConfiguration.GatewayHost = shared.QuicConfiguration.GatewayIP
	client.ClientConfiguration.GatewayPort = shared.QuicConfiguration.GatewayPort
	client.ClientConfiguration.ListenPort = shared.QuicConfiguration.ListenPort
	client.ClientConfiguration.WinDivertThreads = shared.QuicConfiguration.WinDivertThreads
	client.ClientConfiguration.Verbose = shared.QuicConfiguration.Verbose

	execContext, cancelExecutionFunc := context.WithCancel(context.Background())

	if shared.QuicConfiguration.ClientFlag {
		log.Println("Running Client")
		windivert.EnableDiverterLogging(client.ClientConfiguration.Verbose)

		gatewayHost := shared.QuicConfiguration.GatewayIP
		gatewayPort := shared.QuicConfiguration.GatewayPort
		listenHost := shared.QuicConfiguration.ListenIP
		listenPort := shared.QuicConfiguration.ListenPort
		threads := shared.QuicConfiguration.WinDivertThreads

		if windivert.InitializeWinDivertEngine(gatewayHost, listenHost, gatewayPort, listenPort, threads) != windivert.DIVERT_OK {
			windivert.CloseWinDivertEngine()
			os.Exit(1)
		}
		go client.RunClient(execContext)
	} else {
		log.Println("Running Server")
		go server.RunServer(execContext)
	}

	interruptListener := make(chan os.Signal)
	signal.Notify(interruptListener, os.Interrupt, syscall.SIGINT, syscall.SIGTERM)
	<-interruptListener

	cancelExecutionFunc()

	<-execContext.Done()

	log.Println("Shutdown...")
	log.Println(windivert.CloseWinDivertEngine())

	<-time.After(1 * time.Second)

	log.Println("Exiting...")
	os.Exit(1)
}
