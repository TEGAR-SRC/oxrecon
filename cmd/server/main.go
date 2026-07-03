package server

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"
)

type Server struct {
	port    int
	started time.Time
	mux     *http.ServeMux
}

type APIResponse struct {
	Status  int         `json:"status"`
	Message string      `json:"message"`
	Data    any         `json:"data,omitempty"`
	Errors  []APIError  `json:"errors,omitempty"`
}

type APIError struct {
	Field   string `json:"field,omitempty"`
	Message string `json:"message"`
}

func NewServer(port int) *Server {
	s := &Server{
		port:    port,
		started: time.Now(),
		mux:     http.NewServeMux(),
	}
	s.routes()
	return s
}

func (s *Server) Start() error {
	addr := fmt.Sprintf(":%d", s.port)
	log.Printf("WebTool API Server starting on %s", addr)
	return http.ListenAndServe(addr, s.mux)
}

func (s *Server) routes() {
	s.mux.HandleFunc("/api/v1/health", s.handleHealth)
	s.mux.HandleFunc("/api/v1/dns/lookup", s.handleDNSLookup)
	s.mux.HandleFunc("/api/v1/dns/reverse", s.handleDNSReverse)
	s.mux.HandleFunc("/api/v1/whois", s.handleWHOIS)
	s.mux.HandleFunc("/api/v1/ssl/cert", s.handleSSLCert)
	s.mux.HandleFunc("/api/v1/scan", s.handleScan)
	s.mux.HandleFunc("/api/v1/host", s.handleHost)
	s.mux.HandleFunc("/api/v1/port", s.handlePort)
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	respondJSON(w, 200, APIResponse{
		Status:  200,
		Message: "ok",
		Data: map[string]any{
			"version": "1.0.0",
			"uptime":  time.Since(s.started).String(),
		},
	})
}

func (s *Server) handleDNSLookup(w http.ResponseWriter, r *http.Request) {
	domain := r.URL.Query().Get("domain")
	if domain == "" {
		respondJSON(w, 400, APIResponse{
			Status:  400,
			Message: "domain parameter required",
		})
		return
	}
	respondJSON(w, 200, APIResponse{
		Status:  200,
		Message: "ok",
		Data:    map[string]string{"domain": domain},
	})
}

func (s *Server) handleDNSReverse(w http.ResponseWriter, r *http.Request) {
	ip := r.URL.Query().Get("ip")
	if ip == "" {
		respondJSON(w, 400, APIResponse{
			Status:  400,
			Message: "ip parameter required",
		})
		return
	}
	respondJSON(w, 200, APIResponse{
		Status:  200,
		Message: "ok",
		Data:    map[string]string{"ip": ip},
	})
}

func (s *Server) handleWHOIS(w http.ResponseWriter, r *http.Request) {
	domain := r.URL.Query().Get("domain")
	if domain == "" {
		respondJSON(w, 400, APIResponse{
			Status:  400,
			Message: "domain parameter required",
		})
		return
	}
	respondJSON(w, 200, APIResponse{
		Status:  200,
		Message: "ok",
		Data:    map[string]string{"domain": domain},
	})
}

func (s *Server) handleSSLCert(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Query().Get("host")
	if host == "" {
		respondJSON(w, 400, APIResponse{
			Status:  400,
			Message: "host parameter required",
		})
		return
	}
	respondJSON(w, 200, APIResponse{
		Status:  200,
		Message: "ok",
		Data:    map[string]string{"host": host},
	})
}

func (s *Server) handleScan(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		respondJSON(w, 201, APIResponse{
			Status:  201,
			Message: "scan created",
			Data:    map[string]string{"scan_id": "pending"},
		})
		return
	}
	if r.Method == "GET" {
		id := r.URL.Query().Get("id")
		respondJSON(w, 200, APIResponse{
			Status:  200,
			Message: "ok",
			Data:    map[string]string{"scan_id": id, "status": "completed"},
		})
		return
	}
	respondJSON(w, 405, APIResponse{Status: 405, Message: "method not allowed"})
}

func (s *Server) handleHost(w http.ResponseWriter, r *http.Request) {
	ip := r.URL.Query().Get("ip")
	if ip == "" {
		respondJSON(w, 400, APIResponse{Status: 400, Message: "ip parameter required"})
		return
	}
	respondJSON(w, 200, APIResponse{
		Status:  200,
		Message: "ok",
		Data:    map[string]string{"ip": ip},
	})
}

func (s *Server) handlePort(w http.ResponseWriter, r *http.Request) {
	ip := r.URL.Query().Get("ip")
	port := r.URL.Query().Get("port")
	if ip == "" || port == "" {
		respondJSON(w, 400, APIResponse{Status: 400, Message: "ip and port required"})
		return
	}
	respondJSON(w, 200, APIResponse{
		Status:  200,
		Message: "ok",
		Data:    map[string]any{"ip": ip, "port": port},
	})
}

func respondJSON(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}
