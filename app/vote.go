package app

import (
	"errors"
	"fmt"
	"math/rand"
	"net/http"
	"strconv"
	"strings"
	"text/template"

	"github.com/gorilla/mux"
	"github.com/jinzhu/gorm"
	_ "github.com/jinzhu/gorm/dialects/postgres" // cockroachdb
	otp "github.com/pquerna/otp/totp"
	"github.com/wader/gormstore"
	"golang.org/x/crypto/bcrypt"
	"gopkg.in/ini.v1"
)

//App is the container for the voting applciation
// containing the http router, db, and session store.
type App struct {
	Router *mux.Router
	DB     *gorm.DB
	Store  *gormstore.Store
}

var s Settings

// Initialize starts the application
func (a *App) Initialize(filename string) {
	fmt.Println("init")
	cfg, err := ini.Load(filename)
	if err != nil {
		panic(err)
	}
	s = Settings{}
	err = cfg.MapTo(&s)
	fmt.Println(s)
	if err != nil {
		fmt.Println(err)
	}
	a.DB, err = gorm.Open("postgres", s.getDB())
	if err != nil {
		fmt.Println("Error opening DB")
		fmt.Println(err)
	}
	a.DB.AutoMigrate(Voter{}, Issue{}, VoteMap{}, DelegateMap{}, UsernameChange{})

	a.CreateAccount("test", "test", "6455P3ACHPDUM42DDVLVWUXDV3MQ7SPN")

	a.Store = gormstore.New(a.DB, []byte(s.SessionSecret))
	// TODO: Generate code randomly. Change all store codes.
}

//CreateAccount makes an account using a username, password, and totp string
func (a *App) CreateAccount(username string, password string, totp string) error {
	hash, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
	voter := &Voter{
		Username:   username,
		TOTPSecret: totp,
	}
	a.DB.Where("username = ?", username).Find(voter)
	if voter.ID != 0 {
		return errors.New("account already exists")
	}
	voter.PasswordHash = string(hash)
	a.DB.Create(voter)
	return nil
}

//Run executes the http handler for the App.
func (a *App) Run() {
	m := mux.NewRouter()
	m.HandleFunc("/", a.IndexHandler)
	m.HandleFunc("/login", a.LoginHandler)
	m.HandleFunc("/logout", a.LogoutHandler)
	m.HandleFunc("/vote", a.VoteHandler)
	m.HandleFunc("/delegate", a.DelegationHandler)
	m.HandleFunc("/account", a.AccountHandler)
	m.HandleFunc("/admin", a.AdminHandler)
	m.HandleFunc("/admin/create", a.AdminUserCreateHandler)
	m.HandleFunc("/invite", a.InviteHandler)
	m.Use(a.AuthorizationMiddleware)
	fmt.Println(http.ListenAndServe(s.ListenAddr, m))
}

//VoteMap creates a link between a user, a vote, and decides votestatus.
type VoteMap struct {
	gorm.Model
	VoterRefer uint
	IssueRefer uint
	VoteStatus bool
}

//UsernameChange is used to process username change requests // TODO: FEATURE
type UsernameChange struct {
	gorm.Model
	VoterRefer uint
	FullName   string
	Username   string
	ChangePin  uint32
}

//DelegateMap creates a link between voters and delegates.
type DelegateMap struct {
	gorm.Model
	VoterRefer    uint
	Username      string
	DelegateRefer uint
}

// Voter is the user object.
type Voter struct {
	gorm.Model
	Username       string
	TOTPSecret     string
	PasswordHash   string
	PublicKey      string
	Delegate       bool
	IsAdmin        bool
	UpdatePassword bool
	UpdateTOTP     bool
}

// Issue is a bill/resolution/amendment to describe a change to be made.
type Issue struct {
	gorm.Model
	BillType string
	Title    string
	Summary  string `sql:"type:text"`
	Text     string
}

//IssueStatus weird mapping, FIXME!!!
type IssueStatus struct {
	Issues    map[Issue]int
	PageCount int
}

// Settings contains the settings for the application
type Settings struct {
	ListenAddr    string
	DBType        string
	DBUsername    string
	DBPassword    string
	DBName        string
	DBHost        string
	DBPort        string
	SSL           bool
	SessionSecret string
}

//UserGenerate is a way of storing generated users.
type UserGenerate struct {
	Username string
	Password string
	QR       string
}

//UsernameChangeRequest inserts a request for a username change
func UsernameChangeRequest(db *gorm.DB, userID uint, fullName string, newUsername string) {
	uc := &UsernameChange{
		Username:   newUsername,
		FullName:   fullName,
		ChangePin:  rand.Uint32(),
		VoterRefer: userID,
	}
	qc := &UsernameChange{}
	db.Where("voter_refer = ?", userID).First(qc)
	if qc.ID == 0 {
		db.Save(uc)
	}
	fmt.Println(uc)
}

//UsernameChangeRequestExist checks if a username change request exists
func UsernameChangeRequestExist(db *gorm.DB, userID uint) bool {
	qc := &UsernameChange{}
	db.Where("voter_refer = ?", userID).Find(qc)
	return qc.ID != 0
}

//UpdatePassword updates the password of a user id from the old password to the new password.
func UpdatePassword(db *gorm.DB, userid uint, currentPassword string, newPassword string) error {
	if currentPassword == newPassword {
		return errors.New("Must update password")
	}
	voter := &Voter{}
	db.Where("id = ?", userid).First(voter)
	if voter.ID == 0 {
		return errors.New("User not found")
	}
	err := bcrypt.CompareHashAndPassword([]byte(voter.PasswordHash), []byte(currentPassword))
	if err != nil {
		return errors.New("Incorrect password")
	}
	hash, _ := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.MinCost)
	voter.PasswordHash = string(hash)
	db.Save(voter)
	return nil
}

//ValidateUser checks if the user is valid in the SQL database.
func ValidateUser(db *gorm.DB, username string, password string, totp string) (*Voter, error) {
	voter := &Voter{}
	db.Where("username = ?", username).First(voter)
	if voter.ID == 0 {
		return voter, errors.New("no username found")
	}
	err := bcrypt.CompareHashAndPassword([]byte(voter.PasswordHash), []byte(password))
	if err != nil {
		return voter, errors.New("wrong password")
	}
	if !otp.Validate(totp, voter.TOTPSecret) {
		return voter, errors.New("wrong totp")
	}
	return voter, nil
}

func ToggleDelegate(db *gorm.DB, delegateStatus string, voter uint) {
	ds := (delegateStatus == "delegate")
	v := &Voter{}
	db.Where("id = ?", voter).Find(v)
	v.Delegate = ds
	db.Save(v)
	fmt.Printf("%s set delegate status: %v", v.Username, v.Delegate)
}

//UndelegateUser removes a map between a delegate and a user.
func UndelegateUser(db *gorm.DB, voter uint, delegate string) error {
	dm := DelegateMap{}
	d := Voter{}
	fmt.Println(delegate)
	db.Where("username = ?", delegate).First(&d)
	fmt.Println(d.Username, d.ID)
	db.Where("delegate_refer = ?", d.ID).Where("voter_refer = ?", voter).First(&dm)
	if dm.ID != 0 {
		fmt.Println("Found map to delete", dm)
		db.Unscoped().Delete(dm)
		return nil
	}
	return errors.New("Delegate not found")
}

//DelegateUser maps a voter to a delegate. It verifies that the user is actually a delegate
func DelegateUser(db *gorm.DB, voter uint, delegate string) error {
	v := &Voter{}
	db.Where("ID = ?", voter).First(v)
	del := &Voter{}
	fmt.Println("Searching for delegate", delegate)
	db.Where("username = ?", delegate).First(del)

	if v.ID == 0 {
		return errors.New("No voter found")
	}
	if del.ID == 0 || !del.Delegate {
		return errors.New("No delegate found")
	}
	if del.ID == v.ID {
		return errors.New("Can't delegate yourself")
	}
	dm := &DelegateMap{}
	db.Where("voter_refer = ?", v.ID).Where("delegate_refer = ?", del.ID).First(dm)
	if dm.ID == 0 {
		dm.VoterRefer = v.ID
		dm.DelegateRefer = del.ID
		db.Create(dm)
	}
	return nil
}

func (s Settings) getDB() string {
	return fmt.Sprintf(
		"host=%v port=%v user=%v dbname=%v sslmode=disable", s.DBHost, s.DBPort, s.DBUsername, s.DBName)
}

// Invite allows for users to generate an invite code for a new user.
// From the invite, we can create the Voter user.
type Invite struct {
	FirstName     string
	LastName      string
	StreetAddress string
	City          string
	Zip           string
}

// generateVoter creates the actual voter object in the database.
// when a user invite is printed, this is generated using the SOS number and name
func generateVoter(db *gorm.DB, username string) Voter {
	return Voter{}
}

// registerVoter allows a user to set a password
func (v Voter) registerVoter(db *gorm.DB, username string) Voter {
	return v
}

//InviteHandler renders the invite page for users.
func (a App) InviteHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintln(w, "Ima invite you!")
}

//AdminHandler renders the admin page
func (a App) AdminHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintln(w, "Hi admin")

}

func (a App) AdminUserCreateHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintln(w, "U even an admin?")
}

//AccountHandler renders the account page; update password, update username request,
//update token, and become delegate
func (a App) AccountHandler(w http.ResponseWriter, r *http.Request) {
	ses, _ := a.Store.Get(r, "session")
	var err error
	uid := ses.Values["user_id"].(uint)
	if r.Method == http.MethodPost {
		r.ParseForm()

		if r.FormValue("password_change") == "pc" {
			err = UpdatePassword(a.DB, uid,
				r.FormValue("current_password"), r.FormValue("new_password"))
		}

		if r.FormValue("username_change") == "uc" {
			UsernameChangeRequest(a.DB, uid, r.FormValue("name"), r.FormValue("username"))
		}
		if r.FormValue("become_delegate") == "del" {
			ToggleDelegate(a.DB, r.FormValue("delegate"), uid)
		}
	}
	v := Voter{}
	a.DB.Where("ID = ?", uid).Find(&v)
	templates.ExecuteTemplate(w, "account.html", struct {
		Err   error
		UC    bool
		Voter Voter
	}{
		Err:   err,
		UC:    UsernameChangeRequestExist(a.DB, uid),
		Voter: v,
	})
}

//IndexHandler renders the index page
func (a App) IndexHandler(rw http.ResponseWriter, r *http.Request) {
	rw.Write([]byte("<html>"))
	ses, _ := a.Store.Get(r, "session")
	var v Voter
	a.DB.Where("id = ?", ses.Values["user_id"]).Find(&v)
	rw.Write([]byte(fmt.Sprintf("<p>Hello %s</p>", v.Username)))
	rw.Write([]byte("<a href='/vote'>Click here to vote.</a>"))
	var vm []VoteMap
	a.DB.Find(&vm)
	var issueUnique []VoteMap
	a.DB.Select("DISTINCT(issue_refer)").Find(&issueUnique)
	count2 := len(issueUnique)
	rw.Write([]byte(fmt.Sprintf("<p>Total Votes: %d</p> <p>Total Issues Voted On: %v</p>", len(vm), count2)))

	a.DB.Where("voter_refer = ?", ses.Values["user_id"]).Find(&vm)
	rw.Write([]byte(fmt.Sprintf("Your personal votes: %d </html>", len(vm))))
}

var templates = template.Must(template.New("").Funcs(funcMap).ParseGlob("templates/*"))

var funcMap = template.FuncMap{
	// The name "inc" is what the function will be called in the template text.
	"add": func(i int) int {
		return i + 1
	},
	"sub": func(i int) int {
		return i - 1
	},
}

//DelegationHandler allows users to remove/add delegates for their votes.
func (a App) DelegationHandler(w http.ResponseWriter, r *http.Request) {
	username := ""
	ses, err := a.Store.Get(r, "session")
	user := ses.Values["user_id"].(uint)

	fmt.Println(user)

	if r.Method == http.MethodPost {
		r.ParseForm()
		if r.FormValue("removal") == "true" {
			for _, x := range r.Form["remove_user"] {
				err = UndelegateUser(a.DB, user, x)
			}

		}
		if r.FormValue("delegate_trigger") == "true" {

			err = DelegateUser(a.DB, user, r.FormValue("delegate"))
		}

	}
	v := []Voter{}
	a.DB.Joins("join delegate_maps on voters.id = delegate_maps.delegate_refer").Where("delegate_maps.voter_refer = ?", user).Find(&v)
	errorString := ""
	info := []string{username}
	if err != nil {
		fmt.Println(err)
		info = append(info, err.Error())
		errorString = err.Error()
	}
	err = templates.Funcs(funcMap).ExecuteTemplate(w, "delegate.html", struct {
		Voters []Voter
		Err    string
	}{Voters: v, Err: errorString})

}

//AuthorizationMiddleware verifies a user's session. If the session is invalid, it boots them to login.
func (a App) AuthorizationMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ses, err := a.Store.Get(r, "session")
		fmt.Printf("%v - %v accessed %v\n", r.RemoteAddr, ses.Values["username"], r.RequestURI)
		if (err != nil || ses.Values["user_id"] == nil) && !strings.Contains(r.RequestURI, "login") {
			fmt.Println(err)
			http.Redirect(w, r, "/login", http.StatusTemporaryRedirect)
			return
		}
		if strings.Contains(r.RequestURI, "admin") && ses.Values["is_admin"] == nil {
			fmt.Println("Non-admin access")
			http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
			return
		}
		next.ServeHTTP(w, r)
	})
}

//VoteHandler handles the voting method.
func (a App) VoteHandler(w http.ResponseWriter, r *http.Request) {
	//TODO: Redo this entire form.
	r.ParseForm()
	ses, err := a.Store.Get(r, "session")
	if err != nil {
		fmt.Println(err)
	}
	voterID := ses.Values["user_id"].(uint)
	loggedVote := &VoteMap{}
	if r.Method == http.MethodPost {
		for i, x := range r.Form {
			issueID, err := strconv.Atoi(i)
			if err != nil {
				fmt.Println(err)
			}
			fmt.Println(issueID)
			vote := &VoteMap{
				IssueRefer: uint(issueID),
				VoterRefer: voterID,
			}
			loggedVote = &VoteMap{}
			fmt.Println(loggedVote)
			a.DB.Find(loggedVote, vote)
			fmt.Println(loggedVote)
			isAye := (x[0] == "aye")
			fmt.Println(loggedVote)
			vote.VoteStatus = isAye
			//TODO cleanup this shitstorm.
			if x[0] == "undecided" {
				if loggedVote.ID == 0 {
					continue
				}
				fmt.Println(x[0])
				fmt.Println("Deleting records ", loggedVote)

				a.DB.Unscoped().Delete(loggedVote)
			} else if loggedVote.ID == 0 {
				a.DB.Create(vote)
			} else if loggedVote.VoteStatus != isAye {
				loggedVote.VoteStatus = isAye
				a.DB.Save(&loggedVote)
			}
		}
	}

	page, err := strconv.Atoi(r.FormValue("page"))
	if err != nil {
		page = 0
	}
	issues := []Issue{}
	a.DB.Offset(page * 10).Limit(10).Find(&issues)
	issueVoteRecord := IssueStatus{}
	issueVoteRecord.PageCount = page
	issueVoteRecord.Issues = make(map[Issue]int)
	for _, x := range issues {

		loggedVote := &VoteMap{}
		a.DB.Find(loggedVote, &VoteMap{
			IssueRefer: x.ID,
			VoterRefer: voterID,
		})
		voteStatus := 1
		if loggedVote.ID == 0 {
			voteStatus = 2
		}

		if loggedVote.VoteStatus {
			voteStatus = 0
		}
		issueVoteRecord.Issues[x] = voteStatus
	}

	err = templates.Funcs(funcMap).ExecuteTemplate(w, "vote.html", issueVoteRecord)
	if err != nil {
		fmt.Println(err)
	}
}

//LogoutHandler removes the user from login.
func (a App) LogoutHandler(w http.ResponseWriter, r *http.Request) {
	ses, err := a.Store.Get(r, "session")
	if err != nil {
		fmt.Println(err)
	}
	ses.Options.MaxAge = -1
	err = ses.Save(r, w)
	if err != nil {
		fmt.Println(err)
	}
	http.Redirect(w, r, "/login", http.StatusTemporaryRedirect)
}

// LoginHandler logs the login event and validates the user is valid.
// It also renders the login page.
func (a App) LoginHandler(rw http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	var loginErr error
	if r.FormValue("logon") == "Login" {
		var voter *Voter
		voter, loginErr = ValidateUser(a.DB, r.FormValue("username"), r.FormValue("password"), r.FormValue("totp"))
		if loginErr == nil {
			session, _ := a.Store.Get(r, "session")
			session.Values["user_id"] = voter.ID
			session.Values["username"] = voter.Username
			if voter.IsAdmin {
				session.Values["is_admin"] = true
			}
			a.Store.Save(r, rw, session)
			http.Redirect(rw, r, "/", http.StatusTemporaryRedirect)
			return
		}

	}
	templates.ExecuteTemplate(rw, "login.html", loginErr)
}

// InviteHandler allows an authenticated voter to invite another voter
// to the site
func InviteHandler(rw http.ResponseWriter, r *http.Request) {
	templates.ExecuteTemplate(rw, "invite.html", nil)
}
