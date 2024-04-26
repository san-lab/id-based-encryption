package tpkg

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
)

const PUBLIC_KEY_ENDPOINT = "/master-public-key"
const EXTRACT_ENDPOINT = "/extract"
const HEALTH_ENDPOINT = "/health"

var SERVER_PORT = 9000

type ExtractRequest struct {
	Id string `json:"id"`
	// SoulToken...
}

func StartServer() {
	// HTTP routes
	http.HandleFunc(PUBLIC_KEY_ENDPOINT, publicKeyHandler)
	http.HandleFunc(EXTRACT_ENDPOINT, extractHandler)
	http.HandleFunc(HEALTH_ENDPOINT, healthHandler)

	fmt.Println("+ TPKG server running on port", SERVER_PORT)
	err := http.ListenAndServe(fmt.Sprintf(":%d", SERVER_PORT), nil)
	if err != nil {
		fmt.Println("Error starting the server:", err)
	}
}

func publicKeyHandler(w http.ResponseWriter, r *http.Request) {
	pubMasterKey := GetPublicMasterKey()
	pubM, err := pubMasterKey.Marshal()
	if err != nil {
		fmt.Fprintf(w, "Error marshalling the public key")
	}
	fmt.Fprintf(w, "%x", pubM)
}

func extractHandler(w http.ResponseWriter, r *http.Request) {
	body, err := checkForPostRequest(w, r)
	if err != nil {
		return
	}

	request := new(ExtractRequest)
	json.Unmarshal(body, request)
	userPrivKey, err := Extract([]byte(request.Id), nil)
	if err != nil {
		fmt.Fprintf(w, "Error: %s", err)
	}
	fmt.Fprintf(w, "User private Key: %x", userPrivKey.Marshal())
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprint(w, "TPKG health check: Up!")
}

func checkForPostRequest(w http.ResponseWriter, r *http.Request) ([]byte, error) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return nil, errors.New("method not allowed")
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Error reading request body", http.StatusInternalServerError)
		return nil, errors.New("error reading request body")
	}
	return body, nil
}
