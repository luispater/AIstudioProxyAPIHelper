package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/luispater/AIstudioProxyAPIHelper/config"
	"github.com/luispater/AIstudioProxyAPIHelper/proxy"
	"github.com/tidwall/sjson"
	"log"
	"math/rand"
	"net/http"
	"time"
)

// Server API服务结构体
type Server struct {
	config *config.Config
	proxy  *proxy.Proxy
	port   string
}

// DomainRequest 域名请求结构体
type DomainRequest struct {
	Domain string `json:"domain"`
}

// NewServer 创建一个新的API服务
func NewServer(p *proxy.Proxy, port string) *Server {
	return &Server{
		config: config.GetConfig(),
		proxy:  p,
		port:   port,
	}
}

const jsonTemplate = `{"id":"","model":"","object":"chat.completion.chunk","created":0,"choices":[{"index":0,"delta":{"role":"assistant","content":""},"finish_reason":null,"native_finish_reason":null}]}`

// Start 启动API服务
func (s *Server) Start() error {
	// 注册路由
	http.HandleFunc("/addSniffDomain", s.handleAddSniffDomain)
	http.HandleFunc("/removeSniffDomain", s.handleRemoveSniffDomain)
	http.HandleFunc("/getSniffDomains", s.handleGetSniffDomains)
	http.HandleFunc("/getStreamResponse", s.handleGetStreamResponse)

	// 启动服务
	addr := ":" + s.port
	log.Printf("API server started on %s\n", addr)
	return http.ListenAndServe(addr, nil)
}

// handleAddSniffDomain 处理添加嗅探域名的请求
func (s *Server) handleAddSniffDomain(w http.ResponseWriter, r *http.Request) {
	// 只接受POST请求
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// 解析请求体
	var req DomainRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// 添加域名到嗅探列表
	if req.Domain != "" {
		s.config.AddSniffDomain(req.Domain)
		log.Printf("Added domain to sniff: %s", req.Domain)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(fmt.Sprintf("Domain %s added to sniff list", req.Domain)))
	} else {
		http.Error(w, "Domain cannot be empty", http.StatusBadRequest)
	}
}

// handleRemoveSniffDomain 处理移除嗅探域名的请求
func (s *Server) handleRemoveSniffDomain(w http.ResponseWriter, r *http.Request) {
	// 只接受POST请求
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// 解析请求体
	var req DomainRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// 从嗅探列表中移除域名
	if req.Domain != "" {
		s.config.RemoveSniffDomain(req.Domain)
		log.Printf("Removed domain from sniff: %s", req.Domain)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(fmt.Sprintf("Domain %s removed from sniff list", req.Domain)))
	} else {
		http.Error(w, "Domain cannot be empty", http.StatusBadRequest)
	}
}

// handleGetSniffDomains 处理获取所有嗅探域名的请求
func (s *Server) handleGetSniffDomains(w http.ResponseWriter, r *http.Request) {
	// 只接受GET请求
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// 获取所有嗅探域名
	domains := s.config.GetSniffDomains()

	// 返回JSON格式的域名列表
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(domains)
}

func generateRandomString(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[rand.Intn(len(charset))]
	}
	return string(b)
}

// handleGetStreamResponse 处理获取流式响应的请求
func (s *Server) handleGetStreamResponse(w http.ResponseWriter, r *http.Request) {
	// 只接受GET请求
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// 获取SAPISID Cookie
	cookie, err := r.Cookie("SAPISID")
	if err != nil {
		http.Error(w, "SAPISID cookie is required", http.StatusBadRequest)
		return
	}
	sapisid := cookie.Value

	// 设置响应头
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	// 创建一个通知客户端关闭连接的通道
	clientClosed := r.Context().Done()

	// 每5秒发送一次数据
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming unsupported", http.StatusInternalServerError)
		return
	}
	processingCount := 0
	startResoning := false

	randomStr := generateRandomString(7)
	timestamp := time.Now().Unix()
	chatCmplId := fmt.Sprintf("chatcmpl-%s-%d", randomStr, timestamp)

	for {
		select {
		case <-ticker.C:
			// 从Proxy的forwarders中获取数据
			_, data, toolCallsData, errGetForwarderData := s.proxy.GetForwarderData(sapisid)
			if errGetForwarderData != nil {
				if errGetForwarderData.Error() == "done" {
					s.handleDataWrite(w, &startResoning, chatCmplId, timestamp, data, toolCallsData, true)
					_, _ = fmt.Fprint(w, "data: [DONE]\n\n")
					processingCount = 0
					startResoning = false
					randomStr = generateRandomString(7)
					timestamp = time.Now().Unix()
					chatCmplId = fmt.Sprintf("chatcmpl-%s-%d", randomStr, timestamp)
				} else if errGetForwarderData.Error() == "no more data" {
					processingCount++
				} else if errGetForwarderData.Error() == "no forwarder" {
					processingCount++
				}
				if processingCount == 10 {
					_, _ = fmt.Fprintf(w, ": AISTUDIO-PROXY-API-HELPER PROCESSING\n\n")
					processingCount = 0
				}
			} else {
				s.handleDataWrite(w, &startResoning, chatCmplId, timestamp, data, toolCallsData, false)
				processingCount = 0
			}
			flusher.Flush()
		case <-clientClosed:
			// 客户端关闭连接，退出循环
			return
		}
	}
}

func (s *Server) handleDataWrite(w http.ResponseWriter, startResoning *bool, chatCmplId string, timestamp int64, data []byte, toolCallsData []byte, done bool) {
	// 如果有数据，发送数据
	thinkStartIndex := bytes.Index(data, []byte("<think>"))
	thinkEndIndex := bytes.Index(data, []byte("</think>"))

	if thinkStartIndex != -1 && thinkEndIndex == -1 {
		*startResoning = true
		jsonStr, _ := sjson.Set(jsonTemplate, "id", chatCmplId)
		jsonStr, _ = sjson.Set(jsonStr, "model", "model")
		jsonStr, _ = sjson.Set(jsonStr, "created", timestamp)
		jsonStr, _ = sjson.Set(jsonStr, "choices.0.delta.reasoning_content", string(data[thinkStartIndex+7:]))
		jsonStr, _ = sjson.Set(jsonStr, "choices.0.delta.content", "")
		if done {
			if toolCallsData != nil {
				toolCalls, _ := sjson.SetBytes(toolCallsData, "0.id", fmt.Sprintf("call_%s", generateRandomString(22)))
				jsonStr, _ = sjson.SetRaw(jsonStr, "choices.0.delta.tool_calls", string(toolCalls))
			}
			jsonStr, _ = sjson.Set(jsonStr, "choices.0.finish_reason", "stop")
			jsonStr, _ = sjson.Set(jsonStr, "choices.0.native_finish_reason", "stop")
		}
		_, _ = fmt.Fprintf(w, "data: %s\n\n", jsonStr)
	} else if thinkStartIndex == -1 && thinkEndIndex != -1 {
		*startResoning = false
		// think
		jsonStr, _ := sjson.Set(jsonTemplate, "id", chatCmplId)
		jsonStr, _ = sjson.Set(jsonStr, "model", "model")
		jsonStr, _ = sjson.Set(jsonStr, "created", timestamp)
		think := data[:thinkEndIndex]
		jsonStr, _ = sjson.Set(jsonStr, "choices.0.delta.reasoning_content", string(think))
		jsonStr, _ = sjson.Set(jsonStr, "choices.0.delta.content", "")
		_, _ = fmt.Fprintf(w, "data: %s\n\n", jsonStr)

		// body
		if len(data) > thinkEndIndex+8 {
			body := data[thinkEndIndex+8:]
			jsonStr, _ = sjson.Set(jsonTemplate, "id", chatCmplId)
			jsonStr, _ = sjson.Set(jsonStr, "model", "model")
			jsonStr, _ = sjson.Set(jsonStr, "created", timestamp)
			jsonStr, _ = sjson.Set(jsonStr, "choices.0.delta.content", string(body))
			if done {
				if toolCallsData != nil {
					toolCalls, _ := sjson.SetBytes(toolCallsData, "0.id", fmt.Sprintf("call_%s", generateRandomString(22)))
					jsonStr, _ = sjson.SetRaw(jsonStr, "choices.0.delta.tool_calls", string(toolCalls))
				}
				jsonStr, _ = sjson.Set(jsonStr, "choices.0.finish_reason", "stop")
				jsonStr, _ = sjson.Set(jsonStr, "choices.0.native_finish_reason", "stop")
			}

			_, _ = fmt.Fprintf(w, "data: %s\n\n", jsonStr)
		}
	} else if thinkStartIndex != -1 && thinkEndIndex != -1 {
		// think
		jsonStr, _ := sjson.Set(jsonTemplate, "id", chatCmplId)
		jsonStr, _ = sjson.Set(jsonStr, "model", "model")
		jsonStr, _ = sjson.Set(jsonStr, "created", timestamp)
		think := data[thinkStartIndex+7 : thinkEndIndex]
		jsonStr, _ = sjson.Set(jsonStr, "choices.0.delta.reasoning_content", string(think))
		jsonStr, _ = sjson.Set(jsonStr, "choices.0.delta.content", "")
		_, _ = fmt.Fprintf(w, "data: %s\n\n", jsonStr)

		// body
		if len(data) > thinkEndIndex+8 {
			body := data[thinkEndIndex+8:]
			jsonStr, _ = sjson.Set(jsonTemplate, "id", chatCmplId)
			jsonStr, _ = sjson.Set(jsonStr, "model", "model")
			jsonStr, _ = sjson.Set(jsonStr, "created", timestamp)
			jsonStr, _ = sjson.Set(jsonStr, "choices.0.delta.content", string(body))
			if done {
				if toolCallsData != nil {
					toolCalls, _ := sjson.SetBytes(toolCallsData, "0.id", fmt.Sprintf("call_%s", generateRandomString(22)))
					jsonStr, _ = sjson.SetRaw(jsonStr, "choices.0.delta.tool_calls", string(toolCalls))
				}
				jsonStr, _ = sjson.Set(jsonStr, "choices.0.finish_reason", "stop")
				jsonStr, _ = sjson.Set(jsonStr, "choices.0.native_finish_reason", "stop")
			}

			_, _ = fmt.Fprintf(w, "data: %s\n\n", jsonStr)
		}
	} else {
		if *startResoning {
			jsonStr, _ := sjson.Set(jsonTemplate, "id", chatCmplId)
			jsonStr, _ = sjson.Set(jsonStr, "model", "model")
			jsonStr, _ = sjson.Set(jsonStr, "created", timestamp)
			jsonStr, _ = sjson.Set(jsonStr, "choices.0.delta.reasoning_content", string(data))
			jsonStr, _ = sjson.Set(jsonStr, "choices.0.delta.content", "")
			if done {
				if toolCallsData != nil {
					toolCalls, _ := sjson.SetBytes(toolCallsData, "0.id", fmt.Sprintf("call_%s", generateRandomString(22)))
					jsonStr, _ = sjson.SetRaw(jsonStr, "choices.0.delta.tool_calls", string(toolCalls))
				}
				jsonStr, _ = sjson.Set(jsonStr, "choices.0.finish_reason", "stop")
				jsonStr, _ = sjson.Set(jsonStr, "choices.0.native_finish_reason", "stop")
			}

			_, _ = fmt.Fprintf(w, "data: %s\n\n", jsonStr)
		} else {
			jsonStr, _ := sjson.Set(jsonTemplate, "id", chatCmplId)
			jsonStr, _ = sjson.Set(jsonStr, "model", "model")
			jsonStr, _ = sjson.Set(jsonStr, "created", timestamp)
			jsonStr, _ = sjson.Set(jsonStr, "choices.0.delta.content", string(data))
			if done {
				if toolCallsData != nil {
					toolCalls, _ := sjson.SetBytes(toolCallsData, "0.id", fmt.Sprintf("call_%s", generateRandomString(22)))
					jsonStr, _ = sjson.SetRaw(jsonStr, "choices.0.delta.tool_calls", string(toolCalls))
				}
				jsonStr, _ = sjson.Set(jsonStr, "choices.0.finish_reason", "stop")
				jsonStr, _ = sjson.Set(jsonStr, "choices.0.native_finish_reason", "stop")
			}

			_, _ = fmt.Fprintf(w, "data: %s\n\n", jsonStr)
		}
	}
}
