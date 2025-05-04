package main

import (
	"fmt"
	"net/http"
	"time"

	"github.com/gorilla/securecookie"
	"golang.org/x/crypto/bcrypt"
)

var sCookie = securecookie.New(securecookie.GenerateRandomKey(32), securecookie.GenerateRandomKey(32))

func authMiddleware(next http.Handler, cfg *Config) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/login" {
			next.ServeHTTP(w, r)
			return
		}
		var value map[string]string
		if cookie, err := r.Cookie("noc2go"); err == nil {
			if err := sCookie.Decode("noc2go", cookie.Value, &value); err == nil {
				if u := lookupUser(cfg, value["user"]); u != nil {
					next.ServeHTTP(w, r)
					return
				}
			}
		}
		http.Redirect(w, r, "/login", http.StatusFound)
	})
}

func lookupUser(cfg *Config, name string) *UserEntry {
	for i := range cfg.Auth.Users {
		if cfg.Auth.Users[i].Name == name {
			return &cfg.Auth.Users[i]
		}
	}
	return nil
}

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

func renderLoginForm(w http.ResponseWriter, msg string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, `<style>
        body{display:flex;justify-content:center;align-items:center;min-height:100vh;font-family:sans-serif;background:#f3f4f6;margin:0;}
        .card{background:#fff;padding:2rem 3rem;border-radius:12px;box-shadow:0 4px 14px rgba(0,0,0,.1);text-align:center;}
        h1{margin-top:0;margin-bottom:1.5rem;font-size:1.75rem;color:#111827;}
        input{width:100%;padding:.6rem .8rem;margin:.4rem 0;border:1px solid #d1d5db;border-radius:6px;font-size:1rem;}
        button{margin-top:1rem;width:100%;padding:.7rem;border:none;border-radius:8px;background:#2563eb;color:#fff;font-size:1rem;cursor:pointer;}
        .banner{font-weight:600;color:#2563eb;margin-bottom:1rem;letter-spacing:.5px;}
        .err{color:#dc2626;margin-bottom:.8rem;}
    </style>`)

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
