package client

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
)

const ENCRYPT_ENDPOINT = "/encrypt"
const DECRYPT_ENDPOINT = "/decrypt"
const HEALTH_ENDPOINT = "/health"
const PUBLIC_KEY_ENDPOINT = "/master-public-key"

var SERVER_PORT = 9001

type EncryptRequest struct {
	Id        string `json:"id"`
	Plaintext string `json:"plaintext"`
}

type DecryptRequest struct {
	UserPrivKey string `json:"userPrivKey"`
	Ciphertext  string `json:"ciphertext"`
}

func StartServer() {
	// HTTP routes
	http.HandleFunc(ENCRYPT_ENDPOINT, encryptHandler)
	http.HandleFunc(DECRYPT_ENDPOINT, decryptHandler)
	http.HandleFunc(HEALTH_ENDPOINT, healthHandler)
	http.HandleFunc(PUBLIC_KEY_ENDPOINT, publicMasterKeyHandler)

	fmt.Println("+ Client server running on port", SERVER_PORT)
	err := http.ListenAndServe(fmt.Sprintf(":%d", SERVER_PORT), nil)
	if err != nil {
		fmt.Println("Error starting the server:", err)
	}
}

func encryptHandler(w http.ResponseWriter, r *http.Request) {
	body, err := checkForPostRequest(w, r)
	if err != nil {
		return
	}

	request := new(EncryptRequest)
	json.Unmarshal(body, request)

	fmt.Println(string(body))
	fmt.Println(request)
	fmt.Println(request.Plaintext)
	fmt.Println([]byte(request.Plaintext))

	ciphertext, err := Encrypt([]byte(request.Id), []byte(request.Plaintext))

	if err != nil {
		fmt.Fprintf(w, "Error: %s", err)
	}

	ciphertextMarshalled, err := json.Marshal(ciphertext)
	if err != nil {
		fmt.Fprintf(w, "Error: %s", err)
	}
	fmt.Fprintf(w, "Ciphertext: %x", ciphertextMarshalled)
}

func decryptHandler(w http.ResponseWriter, r *http.Request) {
	body, err := checkForPostRequest(w, r)
	if err != nil {
		return
	}

	request := new(DecryptRequest)
	err = json.Unmarshal(body, request)
	if err != nil {
		fmt.Fprintf(w, "Error: %s", err)
	}

	userPrivKey, err := hex.DecodeString(string(request.UserPrivKey))
	if err != nil {
		fmt.Fprintf(w, "Error: %s", err)
	}
	ciphertext, err := hex.DecodeString(string(request.Ciphertext))
	if err != nil {
		fmt.Fprintf(w, "Error: %s", err)
	}

	unmarshalledUserPrivKey := new(bls12381.G2Affine)
	err = unmarshalledUserPrivKey.Unmarshal(userPrivKey)
	if err != nil {
		fmt.Fprintf(w, "Error: %s", err)
	}
	unmarshalledCiphertext := new(BLSCiphertext)
	err = json.Unmarshal(ciphertext, unmarshalledCiphertext)
	if err != nil {
		fmt.Fprintf(w, "Error: %s", err)
	}

	plaintext, err := Decrypt(unmarshalledUserPrivKey, *unmarshalledCiphertext)
	if err != nil {
		fmt.Fprintf(w, "Error: %s", err)
	}
	fmt.Println(plaintext)
	fmt.Fprintf(w, "Plaintext: %s", plaintext)
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprint(w, "Client health check: Up!")
}

func publicMasterKeyHandler(w http.ResponseWriter, r *http.Request) {
	//if bytes.Equal(PublicMasterKey.A.Marshal(), []byte{0}) {
	resp, err := http.Get("http://localhost:9000/master-public-key")
	if err != nil {
		fmt.Fprintf(w, "Error: %s", err)
	}
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Fprintf(w, "Error: %s", err)
	}
	decodedPub, err := hex.DecodeString(string(respBody))
	if err != nil {
		fmt.Fprintf(w, "Error: %s", err)
	}
	err = (&PublicMasterKey).Unmarshal(decodedPub)
	if err != nil {
		fmt.Fprintf(w, "Error: %s", err)
	}
	//}
	pubM, err := PublicMasterKey.Marshal()
	if err != nil {
		fmt.Fprintf(w, "Error: %s", err)
	}
	fmt.Fprintf(w, "Trusted Server Public Master Key: %x", pubM)
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
