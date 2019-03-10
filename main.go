package main

import (
	"fmt"
	"github.com/jinzhu/gorm"
	_ "github.com/jinzhu/gorm/dialects/sqlite"
	"github.com/qor/admin"
	"github.com/qor/auth"
	"github.com/qor/auth/auth_identity"
	"github.com/qor/auth/authority"
	"github.com/qor/auth/claims"
	"github.com/qor/auth/providers/password"
	"github.com/qor/qor"
	"github.com/qor/redirect_back"
	"github.com/qor/roles"
	"github.com/qor/session/manager"
	"net/http"
	"qor-admin-auth-example/auththeme"
	"strings"
	"time"
)

// Product GORM-backend model
type Product struct {
	gorm.Model
	Name        string
	Description string
}

var (
	// Initialize gorm DB
	gormDB, _ = gorm.Open("sqlite3", "sample.db")

	RedirectBack = redirect_back.New(&redirect_back.Config{
		SessionManager:  manager.SessionManager,
		IgnoredPrefixes: []string{"/auth"},
	})

	Auth = auththeme.New(&auth.Config{
		DB:         gormDB,
		UserModel:  User{},
		Redirector: auth.Redirector{RedirectBack},
	})

	// Authority initialize Authority for Authorization
	Authority = authority.New(&authority.Config{
		Auth: Auth,
	})
)

type AdminAuth struct{}

func (AdminAuth) LoginURL(c *admin.Context) string {
	return "/auth/login"
}

func (AdminAuth) LogoutURL(c *admin.Context) string {
	return "/auth/logout"
}

func (AdminAuth) GetCurrentUser(c *admin.Context) qor.CurrentUser {
	currentUser := Auth.GetCurrentUser(c.Request)
	if currentUser != nil {
		qorCurrentUser, ok := currentUser.(qor.CurrentUser)
		if !ok {
			fmt.Printf("User %#v haven't implement qor.CurrentUser interface\n", currentUser)
		}
		return qorCurrentUser
	}
	return nil
}

func init() {
	roles.Register("admin", func(req *http.Request, currentUser interface{}) bool {
		return currentUser != nil && currentUser.(*User).Role == "Admin"
	})
}

var MyAuthorizeHandler = func(context *auth.Context) (*claims.Claims, error) {
	var (
		authInfo    auth_identity.AuthIdentity
		req         = context.Request
		tx          = context.Auth.GetDB(req)
		provider, _ = context.Provider.(*password.Provider)
	)

	req.ParseForm()
	authInfo.Provider = provider.GetName()
	authInfo.UID = strings.TrimSpace(req.Form.Get("login"))

	if tx.Model(context.Auth.AuthIdentityModel).Where(authInfo).Scan(&authInfo).RecordNotFound() {
		return nil, auth.ErrInvalidAccount
	}

	if provider.Config.Confirmable && authInfo.ConfirmedAt == nil {
		currentUser, _ := context.Auth.UserStorer.Get(authInfo.ToClaims(), context)
		provider.Config.ConfirmMailer(authInfo.UID, context, authInfo.ToClaims(), currentUser)

		return nil, password.ErrUnconfirmed
	}

	if err := provider.Encryptor.Compare(authInfo.EncryptedPassword, strings.TrimSpace(req.Form.Get("password"))); err == nil {
		return authInfo.ToClaims(), err
	}

	return nil, auth.ErrInvalidPassword
}

func createAdminUsers() {
	AdminUser := &User{}
	AdminUser.Email = "qortest@dev.com"
	AdminUser.Confirmed = true
	AdminUser.Name = "QOR Admin"
	AdminUser.Role = "Admin"
	gormDB.Create(AdminUser)

	provider := (*auth.Auth).GetProvider(Auth, "password").(*password.Provider)
	hashedPassword, _ := provider.Encryptor.Digest("qortest")
	now := time.Now()

	authIdentity := &auth_identity.AuthIdentity{}
	authIdentity.Provider = "password"
	authIdentity.UID = AdminUser.Email
	authIdentity.EncryptedPassword = hashedPassword
	authIdentity.UserID = fmt.Sprint(AdminUser.ID)
	authIdentity.ConfirmedAt = &now

	gormDB.Create(authIdentity)

	// Send welcome notification
	// Notification.Send(&notification.Message{
	// 	From:        AdminUser,
	// 	To:          AdminUser,
	// 	Title:       "Welcome To QOR Admin",
	// 	Body:        "Welcome To QOR Admin",
	// 	MessageType: "info",
	// }, &qor.Context{DB: DraftDB})
}

func main() {

	gormDB.LogMode(true)
	gormDB.AutoMigrate(&User{}, &Product{}, &auth_identity.AuthIdentity{})
	gormDB.Model(&User{}).AddUniqueIndex("idx_email", "Email")
	gormDB.Model(&auth_identity.AuthIdentity{}).AddUniqueIndex("idx_uuid", "UID")

	Admin := admin.New(&admin.AdminConfig{DB: gormDB, Auth: &AdminAuth{}})

	Auth.RegisterProvider(password.New(&password.Config{
		AuthorizeHandler: MyAuthorizeHandler,
	}))
	Admin.AddResource(&User{})
	Admin.AddResource(&Product{})

	createAdminUsers()
	// Initalize an HTTP request multiplexer
	mux := http.NewServeMux()

	// Mount admin to the mux
	Admin.MountTo("/admin", mux)

	// Mount Auth to Router
	mux.Handle("/auth/", Auth.NewServeMux())

	Authority.Register("logged_in_half_hour", authority.Rule{TimeoutSinceLastLogin: time.Minute * 30})
	fmt.Println("Listening on: 8080")
	http.ListenAndServe(":8080", manager.SessionManager.Middleware(RedirectBack.Middleware(mux)))
}

type User struct {
	gorm.Model
	Email     string `unique;form:"email"`
	Password  string
	Name      string `form:"name"`
	Gender    string
	Role      string
	Confirmed bool
}

func (user User) DisplayName() string {
	return user.Email
}
