package main


import (
	"github.com/LDCS/sflag"
	"github.com/LDCS/qcfg"
	"github.com/LDCS/cim"
	"github.com/LDCS/alertbaseutil"
	"github.com/LDCS/genutil"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"crypto/sha512"
	"encoding/hex"
	"time"
	"encoding/json"
	"log"
	"os/exec"
	
)

const (
	monviewRoot = "../monview/"
)
var (
	passwd          = map[string]string{}
	username        = map[string]string{}
	phonenumber     = map[string]string{}
	email           = map[string]string{}
	numUsers        = 0
	ports           = map[string]string{ "prod" : "1234", "dev" : "1235", "be" : "1236" }
	upSince           time.Time
	currentOperator = ""
	openat2esc      = map[int64]string{}
	openat2sent1    = map[int64]bool{}  // sent to operator ?
	openat2sent2    = map[int64]bool{}  // sent to esc ?
)

var opt = struct{
	Usage       string      "backend for monview"
	Env         string      "Env = prod,dev,be|prod"
	Cfg         string      "Config file|./cfg/monim.cfg"
}{}

type AuthData struct {
	User string
	Hash chan string
}

var getCurrentHashForUser = make(chan *AuthData)
var setCurrentHashForUser = make(chan *AuthData)
var delCurrentHashForUser = make(chan *AuthData)

var alertBaseHost string = ""
var jobMailerPath string = ""
var opsdl string         = ""

var serviceId2DataRequestHandler = map[string]func( w http.ResponseWriter, r *http.Request, usr string ){}

func readConfig() {
	cfg := qcfg.NewCfg("monim.cfg", opt.Cfg, false)
	accntfile := cfg.Str(opt.Env, "core", "passwdfile", "NOFILE")
	if accntfile != "NOFILE" {
		cfg1 := qcfg.NewCfg("passwd.cfg", accntfile, false)
		users := cfg1.GetRows("accnt")
		for _, usr := range users {
			pass := cfg1.Str("accnt", usr, "passwd", "NOPASS" )
			if pass != "NOPASS" {
				passwd[usr]         = pass
				username[usr]       = cfg1.Str("accnt", usr, "name", usr )
				phonenumber[usr]    = cfg1.Str("accnt", usr, "phone", "NA" )
				email[usr]          = cfg1.Str("accnt", usr, "email", "NA" )
			}
		}
	}
	alertBaseHost = cfg.Str(opt.Env, "alerts", "host", "localhost")
	jobMailerPath = cfg.Str(opt.Env, "alerts", "jobmailerpath", "NOMAIL")
	opsdl         = cfg.Str(opt.Env, "alerts", "opsdl", "ops@yourdomain.com")
}

func getCurrOps() {  // Set the value of currentOperator on Monim start
	conn, err := cim.NewCimConnection( alertBaseHost, "alertbase01", fmt.Sprintf("alertbase01-%d", time.Now().UnixNano()) )
	if err != nil {
		fmt.Println("getCurrOps : Cannot connect to alertbase ; err = ", err )
		currentOperator = "NA"
		return
	}
	defer conn.Close()
	res, err := conn.RunCommand("getallopsjson")
	if err != nil {
		fmt.Println("getCurrOps : Cannot run getallopsjson cmd in alertbase via cim ; err =", err)
		currentOperator = "NA"
		return
	}

	var opslst []alertbaseutil.OPSROW
	err = json.Unmarshal([]byte(res), &opslst)
	if err != nil {
		fmt.Println("getCurrOps : Error decoding alertbase output for cmd = getallopsjson; err =", err)
		currentOperator = "NA"
	} else if len(opslst) == 0 {
		currentOperator = "NA"  // No one has ever takenover yet
	} else {
		currentOperator = opslst[0].Opsname
	}
	
}

func createCookie(key, val string) (*http.Cookie) {
	cookie := new(http.Cookie)
	cookie.Name = key
	cookie.Value = val
	cookie.HttpOnly = false
	cookie.Path = "/" // Without this ang js cant read cookies we send
	//cookie.Expires = expire
	return cookie
}

func createBlankCookie(key string) (*http.Cookie) {
	cookie := new(http.Cookie)
	cookie.Name = key
	cookie.Value = ""
	l, _ := time.LoadLocation("UTC")
	cookie.Expires = time.Date(1970, time.January, 1, 0, 0, 0, 0, l)
	cookie.HttpOnly = false
	cookie.Path = "/" // Without this ang js cant read cookies we send
	return cookie
}

func saltedHash(userId, slt string) string {
	hasher := sha512.New()
	hasher.Write([]byte(passwd[userId] + slt))
	sha := hasher.Sum(nil)
	hs1 := make([]byte,128)
	hex.Encode(hs1, sha)
	return string(hs1)
}

func isAuthOK(r *http.Request) (bool, string) {
	/*Check whether the auth cookie is valid*/
	userIdCookie, err1 := r.Cookie("userId")
	hashCookie, err2 := r.Cookie("chash")
	if err1 != nil || err2 != nil {
		return false, ""
	}
	userId := userIdCookie.Value
	hash := hashCookie.Value
	ad := AuthData{User : userId, Hash : make(chan string)}
	getCurrentHashForUser <- &ad
	if hash == <-(ad.Hash) {
		return true, userId
	}
	return false, ""
}


func rootHandler( w http.ResponseWriter, r *http.Request ) {
	if r.URL.Path == "/" {
		http.ServeFile( w, r, monviewRoot + "index.html" )
	} else if strings.HasPrefix( r.URL.Path, "/modules/" ) || strings.HasPrefix( r.URL.Path, "/scripts/" )  || strings.HasPrefix( r.URL.Path, "/lib/" ) {
		http.ServeFile( w, r, monviewRoot + r.URL.Path )
	} else {
		http.NotFound( w, r )
	}
}

func authHandler(  w http.ResponseWriter, r *http.Request ) {
	w.Header().Set("Content-Type", "text/html")
	fmt.Println("Got Login request from ", r.FormValue("userId"))
	userId := r.FormValue("userId")
	tstamp := r.FormValue("tstamp")
	hs := r.FormValue("hash")
	if userId == "" {
		http.Error(w, "Bad Request", 400)
		return
	}
	if saltedHash(userId, tstamp) == hs {
		fmt.Println(userId, ": Authentication Successful")
		ad := AuthData{User:userId, Hash: make(chan string)}
		setCurrentHashForUser <- &ad
		Hash := <-(ad.Hash)
		if Hash == "" {
			http.Error(w, "Server Error", 500)
			return
		}
		// Sent cookie with chash
		cookie := createCookie("chash", Hash)
		http.SetCookie(w, cookie)
		cookie = createCookie("userId", userId)
		http.SetCookie(w, cookie)

	} else {
		fmt.Println(userId, ": Authentication Unsuccessful")
		http.Error(w, "Unauthorized", 401)
		// Send error code
	}
	
}

func logoutHandler( w http.ResponseWriter, r *http.Request ) {
	ok, usr := isAuthOK( r )
	if !ok {
		http.Error( w, "Unauthorized", 401 )
		return
	}
	delCurrentHashForUser <- &AuthData{ User : usr, Hash: make(chan string)}
	fmt.Println("logout req from user = ", usr)
	cookie := createBlankCookie( "chash" )
	http.SetCookie( w, cookie )
	cookie = createBlankCookie( "userId" )
	http.SetCookie( w, cookie )
}

func dataRequestHandler( w http.ResponseWriter, r *http.Request ) {
	ok, usr := isAuthOK( r )
	if !ok {
		http.Error( w, "Unauthorized", 401 )
		return
	}

	serviceId := r.FormValue( "sid" )
	serviceRequestHandler, ok := serviceId2DataRequestHandler[serviceId]
	if !ok {
		http.Error( w, "Bad Request", 400 )
		return
	}

	ad := AuthData{User : usr, Hash: make(chan string)}
	setCurrentHashForUser <- &ad
	Hash := <-(ad.Hash)
	if Hash == "" {
		http.Error( w, "Server Error", 500 )
		return
	}
	// Send new cookie
	cookie := createCookie( "chash", Hash )
	http.SetCookie( w, cookie )
	cookie = createCookie( "userId", usr )
	http.SetCookie( w, cookie )
	
	serviceRequestHandler( w, r, usr )
}

func getInfoBarData( w http.ResponseWriter, r *http.Request, usr string ) {
	fmt.Fprintf(w, `{ "fullname" : "%s",
                          "numusers" : %d,
                          "env" : "%s",
                          "ops" : "%s (%s)",
                          "upsince" : "%s"
                        }`,
		username[usr],
		numUsers,
		opt.Env,
		username[currentOperator], phonenumber[currentOperator],
		upSince.Format("20060102 15:04:05 MST"),
	)
}

func getUserList( w http.ResponseWriter, r *http.Request, usr string ) {
	buf, _ := json.Marshal(username)
	w.Write(buf)
}

func getOpsHistory( w http.ResponseWriter, r *http.Request, usr string ) {
	conn, err := cim.NewCimConnection( alertBaseHost, "alertbase01", fmt.Sprintf("alertbase01-%d", time.Now().UnixNano()) )
	if err != nil {
		http.Error( w, "Monim cannot connect to alertbase", 500 )
		return
	}
	defer conn.Close()
	res, err := conn.RunCommand("getallopsjson")
	if err != nil {
		http.Error( w, "Error running cim command in alertbase", 500 )
		return
	}
	w.Write([]byte(res))
}

func getAlertsJson( w http.ResponseWriter, r *http.Request, usr string ) {
	conn, err := cim.NewCimConnection( alertBaseHost, "alertbase01", fmt.Sprintf("alertbase01-%d", time.Now().UnixNano()) )
	if err != nil {
		http.Error( w, "Monim cannot connect to alertbase", 500 )
		return
	}
	defer conn.Close()
	res, err := conn.RunCommand("getalljson")
	if err != nil {
		http.Error( w, "Error running cim command in alertbase", 500 )
		return
	}
	w.Write([]byte(res))
}

func editAlert( w http.ResponseWriter, r *http.Request, usr string ) {
	editkvplist := r.FormValue( "editkvplist" )
	if editkvplist == "" { return }
	editkvplist, _ = url.QueryUnescape(editkvplist)
	log.Println("Got editalert req from", usr, "editkvplist =", editkvplist)
	conn, err := cim.NewCimConnection( alertBaseHost, "alertbase01", fmt.Sprintf("alertbase01-%d", time.Now().UnixNano()) )
	if err != nil {
		http.Error( w, "Monim cannot connect to alertbase", 500 )
		return
	}
	defer conn.Close()
	res, err := conn.RunCommand("editalert " + editkvplist)
	if err != nil || res != "done" {
		http.Error( w, "Error running cim command in alertbase", 500 )
		return
	}
	alert := new(alertbaseutil.ROW)
	alert.SetFromKVL(editkvplist)
	if alert.Status == "owned" || alert.Status == "closed" {
		owner := usr
		if alert.Owner != "" { owner = alert.Owner }
		closed := ""
		if alert.Status == "closed" { closed = "closed" }
		kk := alert.GetKey()
		if openat2sent2[kk] {

			mailer( openat2esc[kk], fmt.Sprintf( "Alert %s @%s '%s'", closed, owner, alert.Subject ) )
		} else if openat2sent1[kk] {

			mailer( email[currentOperator], fmt.Sprintf( "Alert %s @%s '%s'", closed, owner, alert.Subject ) )
		}
	}
}

func addOps( w http.ResponseWriter, r *http.Request, usr string ) {
	currentOperator = usr
	csvline := fmt.Sprintf("%s,%d", usr, int64(time.Now().UnixNano()/1000000))
	conn, err := cim.NewCimConnection( alertBaseHost, "alertbase01", fmt.Sprintf("alertbase01-%d", time.Now().UnixNano()) )
	if err != nil {
		http.Error( w, "Monim cannot connect to alertbase", 500 )
		return
	}
	defer conn.Close()
	res, err := conn.RunCommand("addops " + csvline)
	if err != nil || res != "done" {
		http.Error( w, "Error running cim command in alertbase", 500 )
		return
	}

	mailer( opsdl, fmt.Sprintf("%s (%s) has taken over", username[usr], phonenumber[usr]) )
}

func registerDataRequestHandlers() {
	//serviceId2DataRequestHandler["service1"]         = servicefunc1
	serviceId2DataRequestHandler["info"]               = getInfoBarData
	serviceId2DataRequestHandler["getalerts"]          = getAlertsJson
	serviceId2DataRequestHandler["editalert"]          = editAlert
	serviceId2DataRequestHandler["addops"]             = addOps
	serviceId2DataRequestHandler["getopshistory"]      = getOpsHistory
	serviceId2DataRequestHandler["getusers"]           = getUserList
}

func mailer( to, subject string ) {
	if to == "" || to == "NA"    { return }
	log.Println("mailer : Sending mail with to =", to, "subject =", subject)
	if jobMailerPath == "NOMAIL" { return }
	cmd := exec.Command(jobMailerPath, "--To", to, "--Subject", subject)
	if cmd != nil {
		cmd.Run()
	}
}

func main() {
	upSince = time.Now()
	sflag.Parse(&opt)
	if ports[opt.Env] == "" {
		fmt.Println("Invalid --Env passed, use one of prod, dev, be")
		return
	}
	readConfig()
	getCurrOps()
	go authServer()
	go alertMailer()
	registerDataRequestHandlers()
	http.HandleFunc( "/", rootHandler )
	http.HandleFunc( "/api/data", dataRequestHandler )
	http.HandleFunc( "/api/authenticate", authHandler )
	http.HandleFunc( "/api/logout", logoutHandler )
	http.ListenAndServe( ":" + ports[opt.Env], nil )
}


//------------------------------ Go routines --------------------------------------------------------------

func alertMailer() {
	
	conn, err := cim.NewCimConnection( alertBaseHost, "alertbase01", fmt.Sprintf("alertbase01-%d", time.Now().UnixNano()) )
	if err != nil {
		log.Println("alertMailer : Cannot connect to alertbase; err =", err)
		conn = nil
	}
	defer func(){ if conn != nil { conn.Close() } }()

	res           := ""
	lastsentesc1  := map[int64]time.Time{}
	lastsentesc2  := map[int64]time.Time{}
	alertlst      := []alertbaseutil.ROW{}
	lastcleanupat := time.Now()

	for {
		if conn == nil {
			log.Println("alertMailer : conn is nil, so trying to reconnect to alertbase")
			conn, err = cim.NewCimConnection( alertBaseHost, "alertbase01", fmt.Sprintf("alertbase01-%d", time.Now().UnixNano()) )
			if err != nil {
				log.Println("alertMailer : Cannot connect to alertbase ; err =", err)
				conn = nil
				time.Sleep(time.Minute)
			}
		}

		if conn != nil && err == nil {
			res, err = conn.RunCommand("getalljson")
			if err != nil {
				log.Println("alertMailer : Error executing 'getalljson' cmd on alertbase via cim, will try reconnecting...")
				conn.Close()
				conn = nil
				time.Sleep(time.Minute)
			} else {
				err = json.Unmarshal([]byte(res), &alertlst)
				if err != nil {
					log.Println("alertMailer : Error decoding alertbase output for cmd = 'getalljson'; err =", err)
				}
			}
		}

		for _, alert := range alertlst {

			kk     := alert.GetKey()
			openat2esc[kk] = alert.Escalate
			if alert.Status != "open" { continue }
			openat := alert.GetOpenat()
			lim1   := openat.Add(time.Duration(genutil.ToInt(alert.Escalatemin1, 10000))*time.Minute)
			lim2   := openat.Add(time.Duration(genutil.ToInt(alert.Escalatemin2, 10000))*time.Minute)
			now    := time.Now()
			if now.After(lim2) && ( now.Sub(lastsentesc2[kk]) >= 5*time.Hour ) {
			
				mailer( alert.Escalate, fmt.Sprintf( "The alert '%s' unowned over %s mins", alert.Subject, alert.Escalatemin2 ) )
				lastsentesc2[kk] = now
				openat2sent2[kk] = true
			} else if now.After(lim1) && now.Before(lim2) && ( now.Sub(lastsentesc1[kk]) >= 10*time.Minute ) {
			
				mailer( email[currentOperator], fmt.Sprintf( "The alert '%s' unowned over %s mins", alert.Subject, alert.Escalatemin1 ) )
				lastsentesc1[kk] = now
				openat2sent1[kk] = true
			}
		}
			
		time.Sleep(time.Minute)  //------------- Polls alertbase every ~ 1min
		
		now := time.Now()
		if now.Sub(lastcleanupat) >= 24*time.Hour {  // -- cleanup every day
			// Time for cleaning up old entries in the lastsentesc* and openat2* maps
			lastcleanupat = now
			kkset := map[int64]bool{}
			for kk, _ := range lastsentesc1 { kkset[kk] = true }
			for kk, _ := range lastsentesc2 { kkset[kk] = true }
			for kk, _ := range openat2esc   { kkset[kk] = true }
			for kk, _ := range openat2sent1 { kkset[kk] = true }
			for kk, _ := range openat2sent2 { kkset[kk] = true }
			lim := int64(now.Add(7*24*time.Hour).UnixNano()/1000000)
			for kk, _ := range kkset {
				if kk <= lim {
					delete(lastsentesc1, kk)
					delete(lastsentesc2, kk)
					delete(openat2esc,   kk)
					delete(openat2sent1, kk)
					delete(openat2sent2, kk)
				}
			}
		}
	}
}

func authServer() {
	var user2hash = map[string]string{}
	var ad *AuthData = nil
	for {
		select {
		case ad = <-getCurrentHashForUser:
			_, ok := passwd[ad.User]
			if !ok {
				ad.Hash <- ""
			} else {
				hs, ok1 := user2hash[ad.User]
				if !ok1 {
					ad.Hash <- ""
				} else {
					ad.Hash <- hs
				}
			}
		case ad = <-setCurrentHashForUser:
			_, ok := passwd[ad.User]
			if !ok {
				ad.Hash <- ""
			} else {
				hs := saltedHash(ad.User, fmt.Sprintf("%d", time.Now().UnixNano()))
				user2hash[ad.User] = hs
				ad.Hash <- hs
			}
		case ad = <-delCurrentHashForUser:

			delete(user2hash, ad.User)
			//ad.Hash <- ""
		}
		numUsers = len(user2hash)
	}
}
