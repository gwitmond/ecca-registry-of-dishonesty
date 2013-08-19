// Ecca Authentication  -  Registry of (dis)honesty
//
// Registry of eccentric authenticated client certificates.
// Keeps Ecca-CA's honest.
//
// Copyright 2013, Guido Witmond <guido@witmond.nl>
// Licensed under AGPL v3 or later. See LICENSE.

// Testing code

package main // ecca-registry

import (
        "testing"
        "testing/quick"
	"encoding/pem"
        "bytes"
	"crypto/rsa"
	CryptoRand "crypto/rand"
	"fmt"
        MathRand   "math/rand"
        "time"
	"github.com/gwitmond/eccentric-authentication" // package eccentric
	"github.com/gwitmond/eccentric-authentication/fpca" // package eccentric/fpca
	"github.com/gwitmond/eccentric-authentication/utils/camaker" // CA maker tools.
)

var  caCert, caKey, _ = camaker.GenerateCA("The Root CA", "CA", 512)
var caCertPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caCert.Raw})
var fpcaCert, fpcaKey, _ = camaker.GenerateFPCA("The FPCA Org", "FPCA-CN", caCert, caKey, 512)
var fpcaCertPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: fpcaCert.Raw})

var fp = fpca.FPCA{
	Namespace: "testRealm",
	CaCert:        fpcaCert,
	CaPrivKey:  fpcaKey,
}

// create the chain certificate
var buf = bytes.NewBuffer(caCertPEM)
var n, _  =  buf.WriteString("\n")
var m, _ =  buf.Write(fpcaCertPEM)
var chainPEM = buf.Bytes()


// simple test to check correct working of datastore routines
func TestMemoryDB(t *testing.T) {
	// sets ds in main.go
	ds = DatastoreOpen(":memory:")
	
	testStoreRetrieve := func(name string) bool {
		// prepare
		 privkey, err := rsa.GenerateKey(CryptoRand.Reader, 384)
		check(err)
		CN := fmt.Sprintf("%s@@%s", name, fp.Namespace)
		clientCert, err := fp.SignClientCert(CN, &privkey.PublicKey)

		// privPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privKey)})
		certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: clientCert})

		expected, err := eccentric.ParseCert(string(certPEM))
		check(err)

		// store what we will expect later on. It must match.
		ds.store(fp.Namespace, name, expected)
		
		// retrieve
		res, err := ds.get_certificates(fp.Namespace, name, certPEM)
		check(err)

		// verify
		if len(res) == 0 {
			fmt.Printf("No results\n")
			return false
		}
		if len(res) > 1 { 
			fmt.Printf("Too many results\n")
			return false
		}
		// The ultimate test: get the expected certificate back.
		retrieved, err := eccentric.ParseCert(string(res[0].Certificate))
		//expected := clientCert
		if expected.Equal(retrieved) == false {
			fmt.Printf("retrieved certificate is not equal to expected certificate\n")
			return false
		}
		return true

	}
	err := quick.Check(testStoreRetrieve, 
		&quick.Config{
			MaxCount: 10,
			Rand: MathRand.New(MathRand.NewSource(time.Now().UnixNano())),
		})
	if err != nil {
		t.Error(err)
	}
}



