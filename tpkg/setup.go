package tpkg

import (
	"github.com/san-lab/id-based-encryption/common"
)

// Setup parameters
var privateMasterKey *common.PrivateKey

func Initialize() {
	if !findMasterPrivateKey() {
		generatePrivateMasterKey()
		saveMasterPrivateKey()
	}

	servePublicKey()
}

func generatePrivateMasterKey() error {
	var err error
	// Calculate (s, sP)
	privateMasterKey, err = common.GenerateKeysG1()
	common.PublicMasterKey = privateMasterKey.PublicKey // set in common for now...
	return err
}

func saveMasterPrivateKey() {
	// save to a file
}

func findMasterPrivateKey() bool {
	// look for priv key in file
	return false
}

func servePublicKey() {
	// serve through http server
}

// will need this if client is not in the same piece of software
func GetPublicMasterKey() common.PublicKey {
	return privateMasterKey.PublicKey
}
