package main

import (
	"flag"
	"fmt"
	"github.com/luispater/AIstudioProxyAPIHelper/api"
	"github.com/luispater/AIstudioProxyAPIHelper/config"
	"github.com/luispater/AIstudioProxyAPIHelper/proxy"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
)

func main() {
	// Parse command line arguments
	var (
		port         string
		apiPort      string
		sniffDomains string
		proxyServer  string
	)

	flag.StringVar(&port, "port", "3120", "Proxy server port")
	flag.StringVar(&apiPort, "api-port", "3121", "API server port")
	flag.StringVar(&sniffDomains, "sniff", "*.google.com", "List of domains to sniff, separated by commas")
	flag.StringVar(&proxyServer, "proxy", "", "Upstream proxy server URL (e.g., http://user:pass@host:port, https://host:port, socks5://user:pass@host:port)")
	flag.Parse()

	// Get configuration
	cfg := config.GetConfig()
	cfg.SetProxyPort(port)

	// Set proxy server if provided
	if proxyServer != "" {
		cfg.SetProxyServerURL(proxyServer)
		log.Printf("Using upstream proxy server: %s", proxyServer)
	}

	// Add domains to sniff
	if sniffDomains != "" {
		domains := strings.Split(sniffDomains, ",")
		for _, domain := range domains {
			domain = strings.TrimSpace(domain)
			if domain != "" {
				cfg.AddSniffDomain(domain)
				log.Printf("Adding domain to sniff: %s", domain)
			}
		}
	}

	// Create proxy server
	p := proxy.NewProxy()

	// Create API server
	apiServer := api.NewServer(p, apiPort)

	// Handle signals
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigChan
		fmt.Println("\nShutting down servers...")
		os.Exit(0)
	}()

	// Start API server in a goroutine
	go func() {
		if err := apiServer.Start(); err != nil {
			log.Fatalf("API server failed to start: %v", err)
		}
	}()

	// Start proxy server in the main goroutine
	if err := p.Start(); err != nil {
		log.Fatalf("Proxy server failed to start: %v", err)
	}
}
