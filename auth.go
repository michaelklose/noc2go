package main

import (
	"fmt"
	"net/http"
	"time"

	"github.com/gorilla/securecookie"
	"golang.org/x/crypto/bcrypt"
)

var sCookie = securecookie.New(securecookie.GenerateRandomKey(32), securecookie.GenerateRandomKey(32))

// ---------------- middleware ----------------
func authMiddleware(next http.Handler, cfg *Config) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// public routes
		if r.URL.Path == "/login" || r.URL.Path == "/passwd" {
			next.ServeHTTP(w, r)
			return
		}
		var value map[string]string
		if cookie, err := r.Cookie("noc2go"); err == nil {
			if err := sCookie.Decode("noc2go", cookie.Value, &value); err == nil {
				if u := lookupUser(cfg, value["user"]); u != nil {
					// attach current user to context (optional)
					next.ServeHTTP(w, r)
					return
				}
			}
		}
		http.Redirect(w, r, "/login", http.StatusFound)
	})
}

// ---------------- user helpers ----------------
func lookupUser(cfg *Config, name string) *UserEntry {
	for i := range cfg.Auth.Users {
		if cfg.Auth.Users[i].Name == name {
			return &cfg.Auth.Users[i]
		}
	}
	return nil
}

// ---------------- handlers ----------------
func handleLogin(cfg *Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			renderLoginForm(w, "")
			return
		}
		user := r.FormValue("user")
		pass := r.FormValue("pass")
		u := lookupUser(cfg, user)
		if u == nil || bcrypt.CompareHashAndPassword([]byte(u.PwHash), []byte(pass)) != nil {
			renderLoginForm(w, "Invalid credentials")
			return
		}
		value := map[string]string{"user": user}
		if encoded, err := sCookie.Encode("noc2go", value); err == nil {
			c := &http.Cookie{Name: "noc2go", Value: encoded, Path: "/", Expires: time.Now().Add(8 * time.Hour), HttpOnly: true, Secure: true}
			http.SetCookie(w, c)
		}
		http.Redirect(w, r, "/", http.StatusSeeOther)
	}
}

func handleLogout() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c := &http.Cookie{Name: "noc2go", Value: "", Path: "/", Expires: time.Unix(0, 0), HttpOnly: true, Secure: true}
		http.SetCookie(w, c)
		http.Redirect(w, r, "/login", http.StatusSeeOther)
	}
}

func handleChangePassword(cfg *Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Only logged‑in users reach this handler via authMiddleware exemption.
		// Identify current user via cookie.
		cookie, err := r.Cookie("noc2go")
		if err != nil {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		var value map[string]string
		if err := sCookie.Decode("noc2go", cookie.Value, &value); err != nil {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		user := lookupUser(cfg, value["user"])
		if user == nil {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}

		if r.Method == http.MethodGet {
			renderPasswdForm(w, "")
			return
		}

		cur := r.FormValue("cur")
		n1 := r.FormValue("new1")
		n2 := r.FormValue("new2")

		if bcrypt.CompareHashAndPassword([]byte(user.PwHash), []byte(cur)) != nil {
			renderPasswdForm(w, "Current password incorrect")
			return
		}
		if n1 == "" || n1 != n2 {
			renderPasswdForm(w, "New passwords do not match")
			return
		}
		hash, _ := bcrypt.GenerateFromPassword([]byte(n1), bcrypt.DefaultCost)
		user.PwHash = string(hash)
		saveConfig(*cfgPath, cfg) // persist change

		// logout after change
		http.Redirect(w, r, "/logout", http.StatusSeeOther)
	}
}

// ---------------- HTML render ----------------
func renderLoginForm(w http.ResponseWriter, msg string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, loginCSS)

	fmt.Fprint(w, `<div class="card">`)
	fmt.Fprint(w, `<div class="banner">NOC2GO</div>`)
	fmt.Fprint(w, `<h1>Login</h1>`)
	if msg != "" {
		fmt.Fprintf(w, `<div class="err">%s</div>`, msg)
	}
	fmt.Fprint(w, `<form method="post">`)
	fmt.Fprint(w, `<input name="user" placeholder="Username" autocomplete="username">`)
	fmt.Fprint(w, `<input type="password" name="pass" placeholder="Password" autocomplete="current-password">`)
	fmt.Fprint(w, `<button>Sign&nbsp;In</button>`)
	fmt.Fprint(w, `</form>`)
	fmt.Fprint(w, `</div>`)
}

func renderPasswdForm(w http.ResponseWriter, msg string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, loginCSS)

	fmt.Fprint(w, `<div class="card">`)
	fmt.Fprint(w, `<div class="banner">NOC2GO</div>`)
	fmt.Fprint(w, `<h1>Change Password</h1>`)
	if msg != "" {
		fmt.Fprintf(w, `<div class="err">%s</div>`, msg)
	}
	fmt.Fprint(w, `<form method="post">`)
	fmt.Fprint(w, `<input type="password" name="cur" placeholder="Current Password" autocomplete="current-password">`)
	fmt.Fprint(w, `<input type="password" name="new1" placeholder="New Password" autocomplete="new-password">`)
	fmt.Fprint(w, `<input type="password" name="new2" placeholder="Repeat New Password" autocomplete="new-password">`)
	fmt.Fprint(w, `<button>Update&nbsp;Password</button>`)
	fmt.Fprint(w, `</form>`)
	fmt.Fprint(w, `</div>`)
}

const loginCSS = `<style>
body{display:flex;justify-content:center;align-items:center;min-height:100vh;font-family:sans-serif;background:#f3f4f6;margin:0;}
.card{background:#fff;padding:2rem 3rem;border-radius:12px;box-shadow:0 4px 14px rgba(0,0,0,.1);text-align:center;min-width:280px;}
h1{margin-top:0;margin-bottom:1.5rem;font-size:1.75rem;color:#111827;}
input{width:100%;padding:.6rem .8rem;margin:.4rem 0;border:1px solid #d1d5db;border-radius:6px;font-size:1rem;}
button{margin-top:1rem;width:100%;padding:.7rem;border:none;border-radius:8px;background:#2563eb;color:#fff;font-size:1rem;cursor:pointer;}
.banner{font-weight:600;color:#2563eb;margin-bottom:1rem;letter-spacing:.5px;}
.err{color:#dc2626;margin-bottom:.8rem;}
</style>`
