// Eccentric Authentication -  Registry of (dis)honesty
//
// Registry of eccentric authenticated client certificates.
// Keeps Ecca-CA's honest.
//
// Copyright 2013, Guido Witmond <guido@witmond.nl>
// Licensed under AGPL v3 or later. See LICENSE.

package main

import (
        "log"
        "net/http"
        "html/template"
	"flag"

	"github.com/gwitmond/eccentric-authentication"  // gives package name 'eccentric'
)

// DBCert contains the Certificate and the Nickname split into <Username> @@ <Realm> to ease queries.
// Raise an stinker when we see multiple Certificates for any {Username, Realm} tuple.
type DBCert struct {
	Username  string
	Realm         string
	Certificate  []byte  // in PEM encoding
}

// The global singletons
var ds *Datastore

// The things to set before running.
var configDir = flag.String("config", "certs", "Directory where the certificates are found.") 
var hostname = flag.String("hostname", "registry-of-honesty.eccentric-authentication.org", "Hostname of the site. Prefix of the TLS server certificate and key file names.")
var bindAddress = flag.String("bind", "[::]:1024", "Address and port number where to bind the listening socket.") 
// End of configuration

var templates = template.Must(template.ParseFiles(
	"templates/homepage.template", 
	"templates/submitForm.template", 
	"templates/submitResult.template",
	"templates/checkForm.template", 
	"templates/checkResult.template",
	"templates/menu.template",
	"templates/tracking.template"))

func init() {
        http.Handle("/", eccentric.AppHandler(homePage))
        http.Handle("/submit", eccentric.AppHandler(submitCert))
        http.Handle("/check", eccentric.AppHandler(checkCert))
        //http.Handle("/proof", eccentric.AppHandler(proofOfHonesty))
        http.Handle("/static/", http.FileServer(http.Dir(".")))
}

func main() {
	ds = DatastoreOpen("honesty.sqlite3")

        log.Printf("Starting. Please visit %v", *bindAddress)
	server6 := &http.Server{Addr: *bindAddress}

	// Set  the server certificate to encrypt the connection with TLS
	tlsCertificate := *configDir + "/" + *hostname + ".cert.pem"
	tlsCertPrivKey   := *configDir + "/" + *hostname + ".key.pem"
        check(server6.ListenAndServeTLS(tlsCertificate, tlsCertPrivKey))
}

func homePage(w http.ResponseWriter, req *http.Request) error {
	// Test for / explicit or we will run for every request that is not handled by other handlers.
        if req.URL.Path == "/" {
		return templates.ExecuteTemplate(w, "homepage.template",  nil)
        }
        http.NotFound(w, req) // 404 - not found
	return nil
}


// submitCert accepts a (PEM-encoded) certificate, validates it
// against the certificate that is found by a DNSSEC lookup of the
// hostname part of the identity in the CN.
// And when validates, record it for future retrieval
func submitCert(w http.ResponseWriter, req *http.Request) error {
	switch req.Method {
        case "GET":          // just show a form to post
		return templates.ExecuteTemplate(w, "submitForm.template", nil)
		
	case "POST":
		// get and validate certificate
		req.ParseForm()
		certPEM := req.Form.Get("certificate")
		// log.Printf("Got certificate: %s\n", cert)
		
		cert, err := eccentric.ParseCert(certPEM)

		site, username, certificate, err := eccentric.ValidateEccentricCertificate(cert)
		log.Printf("username, site are: %s, %s\n", username, site)
		if err != nil { return err }

		err = ds.store(site, username, certificate)   // just store 
		if err != nil { return err }

		certificates, err := ds.get_certificates(site, username)  // here we check for doubles, signifying dishonesty.
		return templates.ExecuteTemplate(w, "submitResult.template", map[string]interface{}{
			"CN": username + "@@" + site,
			"Certificates": certificates,
		})
	}
	http.Error(w, "Unexpected method", http.StatusMethodNotAllowed)
	return nil
}


func checkCert(w http.ResponseWriter, req *http.Request) error {
	// get certificate for given cn
	cn := req.FormValue("cn")
	username, site := eccentric.ParseCN(cn)
	if username == "" || site == "" {
		return templates.ExecuteTemplate(w, "checkForm.template", nil)   // just show a form to get the cn
	}
	certificates, err := ds.get_certificates(site, username)  // here we check for doubles, signifying dishonesty.
	check(err)
	return templates.ExecuteTemplate(w, "checkResult.template", map[string]interface{}{
		"CN": cn,
		"Certificates": certificates,
	})
}


// Utils

// easy way to panic when there's an error
func check(err error) {
        if err != nil {
                panic(err) // TODO: change panic to 500-error.
        }
}


// Return the first (not zeroth) string in the array, if not nil
func getFirst(s []string) string {
        if s != nil {
		return s[1]
        }
        return ""       
}

// The data store.
// Adapt to your data storage facililty. But keep the API.


// var dbmap *gorp.DbMap

// func init() {
// 	db, err := sql.Open("sqlite3", "./honesty.sqlite3")
// 	check(err)
// 	dbmap = &gorp.DbMap{Db: db, Dialect: gorp.SqliteDialect{}}
// 	dbmap.AddTableWithName(DBCert{}, "certificates")  // .SetKeys(false, "Username", "Realm")

// 	dbmap.CreateTables() // if not exists
	
// 	dbmap.TraceOn("[gorp]", log.New(os.Stdout, "myapp:", log.Lmicroseconds)) 
// }



// // Get x509.Certificate structures and convert them to strings.  This
// // way we only store the valid certificate as we've converted it, not
// // any junk that the client provided with it.. (to prevent becoming a
// // movie distro like MegaUpload was)
// func store(site, cn string, cert *x509.Certificate) error {
// 	log.Printf("Storing: %v, %v, %v\n", site, cn, cert.Subject.CommonName)
// 	pemBytes := eccentric.PEMEncode(cert)
// 	// check to see if we have it already (we need to be idempotent).
// 	cur_certs, err := get_certificates(site, cn, pemBytes)
// 	check(err)
// 	if len(cur_certs) > 0 {
// 		return nil // Already have the certificate. pretend we stored it....
// 		// TODO: make a way for the database to do the uniqueness validation instead of us.
// 	}
// 	// We don't have this certificate yet, insert it.
// 	return dbmap.Insert(&DBCert{Username: cn, Realm: site, Certificate: pemBytes})
// }

// // Return the certificates but don't convert to x509.Certificate
// // structures, just output the strings. Caller needs to do the hard
// // work. Don't make it easy to DoS us.
// // args is site, cn, [certificate]
// func get_certificates(args... interface{}) ([]*DBCert, error) {
// 	var query string
// 	switch {
// 	case len(args) == 2:
// 		query = "SELECT * from certificates WHERE realm = ? AND username = ?"
		
// 	case len(args) == 3:
// 		query = "SELECT * from certificates WHERE realm = ? AND username = ? AND certificate = ?"
// 	}
 
// 	certs, err := dbmap.Select(DBCert{}, query, args...)
// 	if err != nil { return nil, err }
	
// 	// certificates := make([]x509.Certificate, len(certs))
// 	log.Printf("Certs are: %#v\n", certs)
// 	var res = make([]*DBCert, len(certs))
// 	for i, dbcert := range certs {
// 		res[i] = dbcert.(*DBCert) // bloody typecast...
// 		// Is this the right way to do this in Go?
// 	}
// 	return res, nil
// }