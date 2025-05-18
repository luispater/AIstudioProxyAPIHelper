package proxy

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"github.com/luispater/AIstudioProxyAPIHelper/config"
	"github.com/luispater/AIstudioProxyAPIHelper/utils"
	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"
	"golang.org/x/net/proxy"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
)

// Proxy proxy struct
type Proxy struct {
	config     *config.Config
	forwarders map[string]*Forwarder
}

// createProxyDialer creates a dialer for the specified proxy URL
func createProxyDialer(proxyURL string) (proxy.Dialer, error) {
	if proxyURL == "" {
		return proxy.Direct, nil
	}

	proxyURLParsed, err := url.Parse(proxyURL)
	if err != nil {
		return nil, fmt.Errorf("invalid proxy URL: %v", err)
	}

	var dialer proxy.Dialer
	switch proxyURLParsed.Scheme {
	case "http", "https":
		dialer = &httpProxyDialer{proxyURL: proxyURLParsed}
	case "socks5":
		auth := &proxy.Auth{}
		if proxyURLParsed.User != nil {
			auth.User = proxyURLParsed.User.Username()
			auth.Password, _ = proxyURLParsed.User.Password()
			dialer, err = proxy.SOCKS5("tcp", proxyURLParsed.Host, auth, proxy.Direct)
		} else {
			dialer, err = proxy.SOCKS5("tcp", proxyURLParsed.Host, nil, proxy.Direct)
		}
	default:
		return nil, fmt.Errorf("unsupported proxy scheme: %s", proxyURLParsed.Scheme)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to create proxy dialer: %v", err)
	}

	return dialer, nil
}

// httpProxyDialer implements proxy.Dialer for HTTP proxies
type httpProxyDialer struct {
	proxyURL *url.URL
}

// Dial connects to the address through the HTTP proxy
func (d *httpProxyDialer) Dial(_, addr string) (net.Conn, error) {
	connectReq := &http.Request{
		Method: "CONNECT",
		URL:    &url.URL{Opaque: addr},
		Host:   addr,
		Header: make(http.Header),
	}

	if d.proxyURL.User != nil {
		password, _ := d.proxyURL.User.Password()
		auth := d.proxyURL.User.Username() + ":" + password
		basicAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte(auth))
		connectReq.Header.Set("Proxy-Authorization", basicAuth)
	}

	conn, err := net.Dial("tcp", d.proxyURL.Host)
	if err != nil {
		return nil, err
	}

	if err = connectReq.Write(conn); err != nil {
		_ = conn.Close()
		return nil, err
	}

	respReader := bufio.NewReader(conn)
	resp, err := http.ReadResponse(respReader, connectReq)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	if resp.StatusCode != 200 {
		_ = conn.Close()
		return nil, fmt.Errorf("proxy error: %s", resp.Status)
	}

	return conn, nil
}

// NewProxy create a new proxy object
func NewProxy() *Proxy {
	return &Proxy{
		config:     config.GetConfig(),
		forwarders: make(map[string]*Forwarder),
	}
}

// Start Start proxy server
func (p *Proxy) Start() error {
	addr := ":" + p.config.GetProxyPort()
	server := &http.Server{
		Addr: addr,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodConnect {
				p.handleHTTPS(w, r)
			} else {
				p.handleHTTP(w, r)
			}
		}),
	}

	log.Printf("Proxy server started on %s\n", addr)
	return server.ListenAndServe()
}

// handleHTTP handle HTTP request
func (p *Proxy) handleHTTP(w http.ResponseWriter, r *http.Request) {
	// check proxy config
	proxyURL := p.config.GetProxyServerURL()
	if proxyURL != "" {
		// create custom transport
		transport := &http.Transport{}

		// parse URL
		parsedURL, err := url.Parse(proxyURL)
		if err != nil {
			log.Printf("Failed to parse proxy URL: %v", err)
			http.Error(w, "Proxy configuration error", http.StatusInternalServerError)
			return
		}

		// set transport type by schema
		switch parsedURL.Scheme {
		case "http", "https":
			transport.Proxy = http.ProxyURL(parsedURL)
		case "socks4", "socks5":
			// create proxy dialer
			dialer, errCreateProxyDialer := createProxyDialer(proxyURL)
			if errCreateProxyDialer != nil {
				log.Printf("Failed to create proxy dialer: %v", errCreateProxyDialer)
				http.Error(w, "Proxy configuration error", http.StatusInternalServerError)
				return
			}

			// set custom dialer
			transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
				return dialer.Dial(network, addr)
			}
		default:
			log.Printf("Unsupported proxy scheme: %s", parsedURL.Scheme)
			http.Error(w, "Unsupported proxy scheme", http.StatusInternalServerError)
			return
		}

		// use custom Transport send request
		resp, err := transport.RoundTrip(r)
		if err != nil {
			log.Printf("Failed to send request through proxy: %v", err)
			http.Error(w, err.Error(), http.StatusServiceUnavailable)
			return
		}
		defer func() {
			_ = resp.Body.Close()
		}()

		// copy response header
		for k, vv := range resp.Header {
			for _, v := range vv {
				w.Header().Add(k, v)
			}
		}
		w.WriteHeader(resp.StatusCode)

		// copy response body
		_, _ = io.Copy(w, resp.Body)
	} else {
		// 使用默认Transport
		resp, err := http.DefaultTransport.RoundTrip(r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusServiceUnavailable)
			return
		}
		defer func() {
			_ = resp.Body.Close()
		}()

		// copy response header
		for k, vv := range resp.Header {
			for _, v := range vv {
				w.Header().Add(k, v)
			}
		}
		w.WriteHeader(resp.StatusCode)

		// copy response body
		_, _ = io.Copy(w, resp.Body)
	}
}

// handleHTTPS handle HTTPS request
func (p *Proxy) handleHTTPS(w http.ResponseWriter, r *http.Request) {
	host := r.Host
	if !strings.Contains(host, ":") {
		host = host + ":443"
	}

	// Check if sniffing is needed
	// p.handleSniffHTTPS(w, r, host)
	if p.config.IsSniffDomain(strings.Split(r.Host, ":")[0]) {
		p.handleSniffHTTPS(w, r, host)
	} else {
		p.handleDirectHTTPS(w, r, host)
	}
}

// handleDirectHTTPS handle direct HTTPS request
func (p *Proxy) handleDirectHTTPS(w http.ResponseWriter, _ *http.Request, host string) {
	var targetConn net.Conn
	var err error

	// check proxy config
	proxyURL := p.config.GetProxyServerURL()
	if proxyURL != "" {
		// create proxy dialer
		dialer, errCreateProxyDialer := createProxyDialer(proxyURL)
		if errCreateProxyDialer != nil {
			log.Printf("Failed to create proxy dialer: %v", errCreateProxyDialer)
			http.Error(w, "Proxy configuration error", http.StatusInternalServerError)
			return
		}

		// use proxy connect to target server
		targetConn, err = dialer.Dial("tcp", host)
		if err != nil {
			log.Printf("Failed to connect to target server through proxy: %v", err)
			http.Error(w, err.Error(), http.StatusServiceUnavailable)
			return
		}
	} else {
		// direct connect to target server
		targetConn, err = net.Dial("tcp", host)
		if err != nil {
			http.Error(w, err.Error(), http.StatusServiceUnavailable)
			return
		}
	}
	defer func() {
		_ = targetConn.Close()
	}()

	// Client connection established notification
	w.WriteHeader(http.StatusOK)

	// Get the raw connection
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Hijacker is unsupported", http.StatusInternalServerError)
		return
	}

	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	defer func() {
		_ = clientConn.Close()
	}()

	var wg sync.WaitGroup
	wg.Add(2)

	// Read Client -> Write Server
	go func() {
		defer wg.Done()
		clientReader := bufio.NewReader(clientConn)
		clientBuf := make([]byte, 4096)

		for {
			n, errRead := clientReader.Read(clientBuf)
			if errRead != nil {
				if errRead != io.EOF {
					if !strings.Contains(errRead.Error(), "use of closed network connection") {
						// log.Printf("Failed to read client data: %v", errRead)
					}
				}
				break
			}

			// forward to server
			_, err = targetConn.Write(clientBuf[:n])
			if err != nil {
				log.Printf("Failed to write server data: %v", err)
				break
			}
		}

		_ = targetConn.(*net.TCPConn).CloseWrite()
	}()

	// Read Server -> Write Client
	go func() {
		defer wg.Done()
		serverReader := bufio.NewReader(targetConn)
		serverBuf := make([]byte, 4096)

		for {
			n, errRead := serverReader.Read(serverBuf)
			if errRead != nil {
				if errRead != io.EOF {
					log.Printf("Failed to read server data: %v", errRead)
				}
				break
			}

			// forward to client
			_, errWrite := clientConn.Write(serverBuf[:n])
			if errWrite != nil {
				log.Printf("Failed to write client data: %v", errWrite)
				break
			}
		}

		_ = clientConn.(*net.TCPConn).CloseWrite()
	}()

	wg.Wait()
}

// handleSniffHTTPS sniffs HTTPS requests
func (p *Proxy) handleSniffHTTPS(w http.ResponseWriter, r *http.Request, host string) {
	log.Printf("Sniff HTTPS requests to %s", host)

	// get domain
	domain := strings.Split(r.Host, ":")[0]

	// create cert
	cert, err := utils.GenerateCertificate(domain)
	if err != nil {
		log.Printf("Failed to generate certificate for %s: %v", domain, err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Client connection established notification.
	w.WriteHeader(http.StatusOK)

	// Get the raw connection
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Hijacker is unsupported", http.StatusInternalServerError)
		return
	}

	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		log.Printf("Failed to Hijack: %v", err)
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	defer func() {
		_ = clientConn.Close()
	}()

	// connect to target server
	var targetConn *tls.Conn

	// check proxy config
	proxyURL := p.config.GetProxyServerURL()
	if proxyURL != "" {
		// 创建代理拨号器
		dialer, errCreateProxyDialer := createProxyDialer(proxyURL)
		if errCreateProxyDialer != nil {
			log.Printf("Failed to create proxy dialer: %v", errCreateProxyDialer)
			return
		}

		// create proxy dialer
		conn, errDial := dialer.Dial("tcp", host)
		if errDial != nil {
			log.Printf("Failed to connect to target server through proxy: %v", errDial)
			return
		}

		// create tls connection
		targetConn = tls.Client(conn, &tls.Config{
			InsecureSkipVerify: true,
		})
		if errHandshake := targetConn.Handshake(); errHandshake != nil {
			log.Printf("TLS handshake with target server failed: %v", errHandshake)
			_ = conn.Close()
			return
		}
	} else {
		// direct connect to target server
		targetConn, err = tls.Dial("tcp", host, &tls.Config{
			InsecureSkipVerify: true,
		})
		if err != nil {
			log.Printf("Failed to connect to the target server: %v", err)
			return
		}
	}
	defer func() {
		_ = targetConn.Close()
	}()

	// Establish a TLS connection with the client.
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{*cert},
	}
	tlsConn := tls.Server(clientConn, tlsConfig)
	err = tlsConn.Handshake()
	if err != nil {
		log.Printf("TLS handshake failed: %v", err)
		return
	}
	defer func() {
		_ = tlsConn.Close()
	}()

	// Variable storing whether to log requests
	var shouldRecord = false
	var requestData bytes.Buffer

	// Forward data in both directions and record it
	var wg sync.WaitGroup
	wg.Add(2)

	disconnect := make(chan bool)
	responseBuffer := make(chan []byte)
	sapisid := ""
	// Read Client -> Write Server
	go func() {
		defer wg.Done()
		clientReader := bufio.NewReader(tlsConn)
		clientBuf := make([]byte, 4096)

		for {
			n, errRead := clientReader.Read(clientBuf)
			if errRead != nil {
				if !strings.Contains(errRead.Error(), "use of closed network connection") {
					// log.Printf("Failed to read client data: %v", errRead)
				}
				// Notification has been disconnected
				disconnect <- true
				break
			}

			// Check if URL contains GenerateContent
			if !shouldRecord && strings.Contains(string(clientBuf[:n]), "GenerateContent") {
				shouldRecord = true
			}

			if shouldRecord {
				requestData.Write(clientBuf[:n])

				if sapisid == "" {
					pattern := `Cookie: .*?SAPISID=([^;]+);`
					re := regexp.MustCompile(pattern)
					matches := re.FindAllStringSubmatch(string(clientBuf[:n]), -1)
					if len(matches) > 0 {
						sapisid = matches[0][1]
					}
				}
			}

			_, err = targetConn.Write(clientBuf[:n])
			if err != nil {
				log.Printf("Failed to write server data: %v", err)
				// Notification has been disconnected
				disconnect <- true
				break
			}
		}

		_ = targetConn.CloseWrite()
	}()

	// Read Server -> Write Client
	go func() {
		defer wg.Done()
		serverReader := bufio.NewReader(targetConn)

		for {
			serverBuf := make([]byte, 4096)
			n, errRead := serverReader.Read(serverBuf)
			if errRead != nil {
				if errRead != io.EOF {
					log.Printf("Failed to read server data: %v", errRead)
				} else {
					log.Printf("Failed to read server data: %v", errRead)
				}
				// Notification has been disconnected
				disconnect <- true
				break
			}

			if shouldRecord {
				data := serverBuf[:n]
				responseBuffer <- data
			}

			_, errWrite := tlsConn.Write(serverBuf[:n])
			if errWrite != nil {
				log.Printf("Failed to write client data: %v", errWrite)
				// Notification has been disconnected
				disconnect <- true
				break
			}

			// Check for end of response (simple check: HTTP/1.1 chunked terminator)
			if n >= 5 && bytes.Equal(serverBuf[:5], []byte("0\r\n\r\n")) {
				disconnect <- true
				break
			}
		}

		err = tlsConn.CloseWrite()
		if err != nil {
			return
		}
	}()

	// Listen for the disconnect signal and close the connection promptly
	go func() {
		<-disconnect
		_ = tlsConn.Close()
		_ = targetConn.Close()
		_ = clientConn.Close()
	}()

	go func() {
		hasAllHeader := false
		responseHeader := make([]byte, 0)
		responseBody := make([]byte, 0)
		// origResponseBody := make([]byte, 0)
		var transferEncoding string

		dataBuffer := make([]byte, 0)
		lastOutputPos := 0
	outLoop:
		for {
			select {
			case data := <-responseBuffer:
				// origResponseBody = append(origResponseBody, data...)
				if !hasAllHeader {
					sIdx := bytes.Index(data, []byte("\r\n\r\n"))
					if sIdx != -1 {
						responseHeader = append(responseHeader, data[0:sIdx]...)
						responseBody = append(responseBody, data[sIdx+4:]...)
						// origResponseBody = append(origResponseBody, data[sIdx+4:]...)

						hasAllHeader = true
					} else {
						responseHeader = append(responseHeader, data...)
					}
				} else {
					if bytes.Contains(responseHeader, []byte("Transfer-Encoding: chunked")) {
						transferEncoding = "chunked"
					}
					responseBody = append(responseBody, data...)
					// origResponseBody = append(origResponseBody, data...)
					if transferEncoding == "chunked" {
						for {
							lengthCrlfIdx := bytes.Index(responseBody, []byte("\r\n"))
							if lengthCrlfIdx == -1 {
								break
							}
							hexLength := responseBody[:lengthCrlfIdx]
							length, errParseInt := strconv.ParseInt(string(hexLength), 16, 64)
							if errParseInt != nil {
								log.Printf("Parsing chunked length failed: %v", errParseInt)
								hasAllHeader = false
								responseHeader = make([]byte, 0)
								responseBody = make([]byte, 0)
								transferEncoding = ""
								break
							}
							if length == 0 {
								if len(responseBody) >= 5 {
									if bytes.Equal(responseBody[:5], []byte("0\r\n\r\n")) {
										hasAllHeader = false
										responseHeader = make([]byte, 0)
										responseBody = make([]byte, 0)
										transferEncoding = ""
										break
									}
								}
							}
							if int(length)+2 > len(responseBody) {
								break
							}

							chunkedData := responseBody[lengthCrlfIdx+2 : lengthCrlfIdx+2+int(length)]
							if lengthCrlfIdx+2+int(length)+2 > len(responseBody) {
								continue
							}
							responseBody = responseBody[lengthCrlfIdx+2+int(length)+2:]
							if bytes.Contains(responseHeader, []byte("Content-Encoding: gzip")) {
								dataBuffer = append(dataBuffer, chunkedData...)
								result, toolCalls, _ := decompressGzip(dataBuffer)
								if result != nil {
									if len(result) > lastOutputPos {
										p.toForwarder(sapisid, result, toolCalls, lastOutputPos, false)
										lastOutputPos = len(result)
									}
								}
							}
						}
					}
				}
			case <-disconnect:
				break outLoop
			}
		}

		result, toolCalls, _ := decompressGzip(dataBuffer)
		if result != nil {
			p.toForwarder(sapisid, result, toolCalls, lastOutputPos, true)
			lastOutputPos = len(result)
		}

	}()

	wg.Wait()
}

func (p *Proxy) toForwarder(sapisid string, result []byte, toolCalls []byte, lastOutputPos int, done bool) {
	if _, hasKey := p.forwarders[sapisid]; !hasKey {
		p.forwarders[sapisid] = NewForwarder()
	}

	if lastOutputPos == 0 {
		p.forwarders[sapisid].Write(result)
	} else {
		if lastOutputPos < len(result) {
			p.forwarders[sapisid].Write(result[lastOutputPos:])
		}
	}

	if done {
		// should be creating a byte array write once
		data := make([]byte, 0)
		if toolCalls != nil {
			// toolcalls
			data = append(data, []byte{0, 0, 0, 1}...)
			data = append(data, toolCalls...)
		}
		data = append(data, []byte{0, 0, 0, 0}...)
		p.forwarders[sapisid].Write(data)
	}
}

func (p *Proxy) GetForwarderData(sapisid string) (int, []byte, []byte, error) {
	if forwarder, exists := p.forwarders[sapisid]; exists {
		return forwarder.Read()
	}
	return 0, nil, nil, fmt.Errorf("no forwarder")
}

func decompressGzip(dataBuffer []byte) ([]byte, []byte, error) {
	buffer := bytes.NewBuffer(dataBuffer)
	gzReader, errReader := gzip.NewReader(buffer)
	if errReader != nil {
		return nil, nil, errReader
	}
	result := make([]byte, 0)
	for {
		buf := make([]byte, 4096)
		n, errRead := gzReader.Read(buf)
		if errRead != nil {
			if errRead == io.EOF {
				// log.Printf("EOF")
			} else {
				// log.Printf("Unknow error: %v", errRead)
			}
			break
		}
		if n > 0 {
			result = append(result, buf[:n-1]...)
		}
	}
	_ = gzReader.Close()

	pattern := `\[\[\[null,(.*?)]],"model"]`
	re := regexp.MustCompile(pattern)

	think := ""
	body := ""
	toolCalls := ""
	input := string(result)
	matches := re.FindAllString(input, -1)
	for _, match := range matches {
		value := gjson.Get(match, "0.0")
		if value.IsArray() {
			arr := value.Array()
			if len(arr) == 2 {
				body = body + arr[1].String()
			} else if len(arr) == 11 && arr[1].Type == gjson.Null && arr[10].Type == gjson.JSON {
				if !arr[10].IsArray() {
					continue
				}
				arrayToolCalls := arr[10].Array()
				funcName := arrayToolCalls[0].String()
				argumentsStr := arrayToolCalls[1].String()
				params := parseToolCallParams(argumentsStr)

				toolCallsTemplate := `[{"id":"","index":0,"type":"function","function":{"name":"","arguments":""}}]`
				toolCalls, _ = sjson.Set(toolCallsTemplate, "0.function.name", funcName)
				toolCalls, _ = sjson.Set(toolCalls, "0.function.arguments", params)
			} else if len(arr) > 2 {
				think = think + arr[1].String()
			}
		}
	}

	if body != "" {
		if think != "" {
			result = []byte(fmt.Sprintf("<think>%s</think>%s", think, body))
		} else {
			result = []byte(body)
		}
	} else {
		if think != "" {
			result = []byte("<think>" + think)
		}
	}

	var byteToolCalls []byte
	if toolCalls != "" {
		byteToolCalls = []byte(toolCalls)
	} else {
		byteToolCalls = nil
	}

	return result, byteToolCalls, nil
}

func parseToolCallParams(argumentsStr string) string {
	arguments := gjson.Get(argumentsStr, "0")
	if !arguments.IsArray() {
		return ""
	}
	funcParams := `{}`
	args := arguments.Array()
	for i := 0; i < len(args); i++ {
		if args[i].IsArray() {
			arg := args[i].String()
			paramName := gjson.Get(arg, "0")
			paramValue := gjson.Get(arg, "1")
			if paramValue.IsArray() {
				v := paramValue.Array()
				if len(v) == 1 { // null
					funcParams, _ = sjson.Set(funcParams, paramName.String(), nil)
				} else if len(v) == 2 { // number and integer
					funcParams, _ = sjson.Set(funcParams, paramName.String(), v[1].Value())
				} else if len(v) == 3 { // string
					funcParams, _ = sjson.Set(funcParams, paramName.String(), v[2].String())
				} else if len(v) == 4 { // Boolean
					funcParams, _ = sjson.Set(funcParams, paramName.String(), v[3].Int() == 1)
				} else if len(v) == 5 { // object
					result := parseToolCallParams(v[4].Raw)
					if result == "" {
						funcParams, _ = sjson.Set(funcParams, paramName.String(), nil)
					} else {
						funcParams, _ = sjson.SetRaw(funcParams, paramName.String(), result)
					}
				}
			}
		}
	}
	return funcParams
}
