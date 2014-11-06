// Eccentric Authentication  -  Registry of (Dis)honesty
//
// Registry of eccentric authenticated client certificates.
// Keeps Ecca-CA's honest.
//
// Copyright 2013, Guido Witmond <guido@witmond.nl>
// Licensed under AGPL v3 or later. See LICENSE

package main

// This file contains the data storage bits

import (
	"crypto/x509"
	"log"
	"os"
	"strings"
	
	"github.com/gwitmond/eccentric-authentication"  // gives package name 'eccentric'

        "github.com/coopernurse/gorp"
        "database/sql"
        _ "github.com/mattn/go-sqlite3"
)

type Datastore struct {
	Storename   string
	dbmap *gorp.DbMap
}

func DatastoreOpen(storename string) (*Datastore) {
        db, err := sql.Open("sqlite3", storename)
        check(err)
 	dbmap := &gorp.DbMap{Db: db, Dialect: gorp.SqliteDialect{}}
	//Do NOT set key to be unique. We want to detect multiple CN's. That's our primary objective!
        dbmap.AddTableWithName(DBCert{}, "certificates")
	dbmap.CreateTablesIfNotExists()
        dbmap.TraceOn("[gorp]", log.New(os.Stdout, "ecca-registry:", log.Lmicroseconds)) 
	return &Datastore{
		Storename: storename,
		dbmap: dbmap,
	}
}
// Get x509.Certificate structures and convert them to strings.  This
// way we only store the valid certificate as we've converted it, not
// any junk that the client provided with it.. (to prevent becoming a
// movie distro like MegaUpload was)
func (ds *Datastore) store(site, cn string, cert *x509.Certificate) error {
	log.Printf("Storing: %v, %v, %v\n", site, cn, cert.Subject.CommonName)
	pemBytes := eccentric.PEMEncode(cert)
	// check to see if we have it already (we need to be idempotent).
	cur_certs, err := ds.get_certificates(site, cn, pemBytes)
	check(err)
	if len(cur_certs) > 0 {
		return nil // Already have the certificate. pretend we stored it....
		// TODO: make a way for the database to do the uniqueness validation instead of us.
	}
	// We don't have this certificate yet, insert it.
	//return ds.dbmap.Insert(&DBCert{Username: strings.ToLower(cn), Realm: strings.ToLower(site), Certificate: pemBytes})
	return ds.insert(strings.ToLower(site), strings.ToLower(cn), pemBytes)
}

// Return the certificates but don't convert to x509.Certificate
// structures, just output the strings. Caller needs to do the hard
// work. Don't make it easy to DoS us.
// arguments are site, cn, [certificate]
// Caller must make site and cn lower case
func (ds *Datastore) get_certificates(site, cn string, args... interface{}) (certs []*DBCert, err error) {
	var query string
	switch {
	case len(args) == 0:
		query = "SELECT * from certificates WHERE realm = ? AND username = ?"
		_, err = ds.dbmap.Select(&certs, query, strings.ToLower(site), strings.ToLower(cn))
		if err != nil { return nil, err } 
	case len(args) == 1:
		query = "SELECT * from certificates WHERE realm = ? AND username = ? AND certificate = ?"
		_, err = ds.dbmap.Select(&certs, query, strings.ToLower(site), strings.ToLower(cn), args[0])
		if err != nil { return nil, err } 

	}
	return // certs, err
}

// Insert certificate but make the site and cn lower case. 
// This matches expectations with email addresses.
func (ds *Datastore) insert(site, cn string, pemBytes []byte) error {
	return ds.dbmap.Insert(&DBCert{Username: strings.ToLower(cn), Realm: strings.ToLower(site), Certificate: pemBytes})
}