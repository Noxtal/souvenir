package main

import (
	"bytes"
	"crypto/aes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"html/template"
	"log"
	"math/big"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"time"

	"github.com/gorilla/mux"
	"golang.org/x/crypto/bcrypt"
	"gopkg.in/yaml.v3"
)

// https://gist.github.com/nanmu42/b838acc10d393bc51cb861128ce7f89c
func pkcs7strip(data []byte, blockSize int) ([]byte, error) {
	length := len(data)
	if length == 0 {
		return nil, errors.New("pkcs7: Data is empty")
	}
	if length%blockSize != 0 {
		return nil, errors.New("pkcs7: Data is not block-aligned")
	}
	padLen := int(data[length-1])
	ref := bytes.Repeat([]byte{byte(padLen)}, padLen)
	if padLen > blockSize || padLen == 0 || !bytes.HasSuffix(data, ref) {
		return nil, errors.New("pkcs7: Invalid padding")
	}
	return data[:length-padLen], nil
}

func pkcs7pad(data []byte, blockSize int) ([]byte, error) {
	if blockSize < 0 || blockSize > 256 {
		return nil, fmt.Errorf("pkcs7: Invalid block size %d", blockSize)
	} else {
		padLen := blockSize - len(data)%blockSize
		padding := bytes.Repeat([]byte{byte(padLen)}, padLen)
		return append(data, padding...), nil
	}
}

// https://stackoverflow.com/questions/39320371/how-start-web-server-to-open-page-in-browser-in-golang
func BrowseTo(url string) error {
	var cmd string
	var args []string

	switch runtime.GOOS {
	case "windows":
		cmd = "cmd"
		args = []string{"/c", "start"}
	case "darwin":
		cmd = "open"
	default: // "linux", "freebsd", "openbsd", "netbsd"
		cmd = "xdg-open"
	}
	args = append(args, url)
	return exec.Command(cmd, args...).Start()
}

func OpenSave() (map[string]interface{}, error) {
	if _, err := os.Stat("souvenir.yaml"); os.IsNotExist(err) {
		_, err = os.Create("souvenir.yaml")
		if err != nil {
			return nil, err
		}
	}

	yfile, err := os.ReadFile("souvenir.yaml")
	if err != nil {
		return nil, err
	}

	data := make(map[string]interface{})

	err = yaml.Unmarshal(yfile, &data)

	if err != nil {
		return nil, err
	}

	return data, nil
}

func WriteSave(data map[string]interface{}) error {
	d, err := yaml.Marshal(&data)
	if err != nil {
		return err
	}

	err = os.WriteFile("souvenir.yaml", d, 0600)
	if err != nil {
		return err
	}

	return nil
}

type Session struct {
	Expiry   time.Time
	Password []byte
}

var sessions = map[string]Session{}

const MASTERKEY_FIELD = "masterkey"
const CHARSET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
const CHARSET_LEN = int64(len(CHARSET))

// https://auth0.com/blog/hashing-in-action-understanding-bcrypt/
var BCRYPT_COST = 12

func OpenSession(w http.ResponseWriter, password string) {
	b := make([]byte, 20)
	for i := 0; i < 20; i++ {
		n, _ := rand.Int(rand.Reader, big.NewInt(CHARSET_LEN))
		b[i] = CHARSET[n.Int64()]
	}

	cookie := string(b)
	expires := time.Now().Add(time.Hour)

	http.SetCookie(w, &http.Cookie{
		Name:    "session",
		Value:   cookie,
		Expires: expires,
		Path:    "/",
	})

	sessions[cookie] = Session{
		Expiry:   expires,
		Password: []byte(password),
	}
}

func SessionPassword(cookie string) ([]byte, bool) {
	session, ok := sessions[cookie]
	if ok {
		if session.Expiry.After(time.Now()) {
			return session.Password, true
		}
	}

	return []byte{}, false
}

func main() {
	fmt.Println("souvenir v0.1 by Noxtal")
	log.Println("Establishing ideal hashing cost...")
	// https://stackoverflow.com/questions/4443476/optimal-bcrypt-work-factor
	var elapsed int64
	elapsed = 0
	cost := bcrypt.MinCost
	for elapsed < 250 {
		before := time.Now().UnixMilli()
		_, err := bcrypt.GenerateFromPassword([]byte("benchmark"), cost)
		if err != nil {
			panic(err)
		}
		after := time.Now().UnixMilli()
		elapsed = after - before
		cost += 1
	}
	BCRYPT_COST = cost

	log.Println("Routing...")
	r := mux.NewRouter()

	r.HandleFunc("/", Index)

	r.HandleFunc("/login", Login)
	r.HandleFunc("/logout", Logout)
	r.HandleFunc("/services/{service}", Service)

	r.HandleFunc("/api/register", ApiRegister).Methods("POST")
	r.HandleFunc("/api/login", ApiLogin).Methods("POST")
	r.HandleFunc("/api/edit", ApiEdit).Methods("POST")

	fs := http.FileServer(http.Dir("./static/"))
	r.PathPrefix("/static/").Handler(http.StripPrefix("/static/", fs))

	log.Println("Listening on port 4444...")
	err := BrowseTo("http://localhost:4444")
	if err != nil {
		panic(err)
	}
	err = http.ListenAndServe("localhost:4444", r)
	if err != nil {
		panic(err)
	}
}

func Index(w http.ResponseWriter, r *http.Request) {
	lp := filepath.Join("templates", "layout.html")
	fp := filepath.Join("templates", "index.html")

	data, err := OpenSave()
	if err != nil {
		fmt.Println(err)
	}

	c, err := r.Cookie("session")
	if err == nil {
		if masterkey, ok := SessionPassword(c.Value); ok {
			if hash, ok := data[MASTERKEY_FIELD]; ok {
				if bcrypt.CompareHashAndPassword([]byte(fmt.Sprintf("%v", hash)), masterkey) == nil {

					data, err := OpenSave()
					if err != nil {
						w.WriteHeader(http.StatusInternalServerError)
						return
					}

					var services []string

					for s := range data {
						if s != MASTERKEY_FIELD {
							services = append(services, s)
						}
					}

					tmpl, _ := template.ParseFiles(lp, fp)
					err = tmpl.ExecuteTemplate(w, "layout", services)

					if err != nil {
						w.WriteHeader(http.StatusInternalServerError)
					}

					return
				}
			}
		}
	}

	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func Login(w http.ResponseWriter, r *http.Request) {
	lp := filepath.Join("templates", "layout.html")
	fp := filepath.Join("templates", "login.html")

	data, err := OpenSave()
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	c, err := r.Cookie("session")
	if err == nil {
		if masterkey, ok := SessionPassword(c.Value); ok {
			if hash, ok := data[MASTERKEY_FIELD]; ok {
				if bcrypt.CompareHashAndPassword([]byte(fmt.Sprintf("%v", hash)), masterkey) == nil {
					http.Redirect(w, r, "/", http.StatusSeeOther)
					return
				}
			}
		}
	}

	_, registered := data[MASTERKEY_FIELD]

	tmpl, _ := template.ParseFiles(lp, fp)
	err = tmpl.ExecuteTemplate(w, "layout", registered)

	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
	}
}

func Logout(w http.ResponseWriter, r *http.Request) {
	c, err := r.Cookie("session")
	if err == nil {
		delete(sessions, c.Value)
	}

	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func Service(w http.ResponseWriter, r *http.Request) {
	lp := filepath.Join("templates", "layout.html")
	fp := filepath.Join("templates", "service.html")

	c, err := r.Cookie("session")
	if err != nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	masterkey, ok := SessionPassword(c.Value)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	service, ok := mux.Vars(r)["service"]
	if !ok {
		w.WriteHeader(http.StatusForbidden)
		return
	}

	data, err := OpenSave()
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	if hash, ok := data[MASTERKEY_FIELD]; ok {
		if bcrypt.CompareHashAndPassword([]byte(fmt.Sprintf("%v", hash)), masterkey) == nil {
			if serviceData, ok := data[service]; ok {
				username := fmt.Sprintf("%v", serviceData.(map[string]interface{})["username"])
				password := fmt.Sprintf("%v", serviceData.(map[string]interface{})["password"])
				decoded, err := base64.StdEncoding.DecodeString(password)
				if err != nil {
					w.WriteHeader(http.StatusInternalServerError)
					return
				}

				key := sha256.Sum256(masterkey)
				cipher, err := aes.NewCipher(key[:])
				if err != nil {
					w.WriteHeader(http.StatusInternalServerError)
					return
				}

				decrypted := make([]byte, len(decoded))
				cipher.Decrypt(decrypted, decoded)

				unpadded, err := pkcs7strip(decrypted, cipher.BlockSize())
				if err != nil {
					w.WriteHeader(http.StatusInternalServerError)
					return
				}

				tmpl, _ := template.ParseFiles(lp, fp)
				err = tmpl.ExecuteTemplate(w, "layout", map[string]interface{}{"Service": service, "Username": username, "Password": string(unpadded)})
				if err != nil {
					w.WriteHeader(http.StatusInternalServerError)
				}
			} else {
				w.WriteHeader(http.StatusNotFound)
			}
		} else {
			w.WriteHeader(http.StatusForbidden)
		}
	} else {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
	}
}

func ApiRegister(w http.ResponseWriter, r *http.Request) {
	err := r.ParseForm()
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	masterkey, ok := r.Form["masterkey"]
	if !ok {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	data, err := OpenSave()
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	if _, ok := data[MASTERKEY_FIELD]; ok {
		w.WriteHeader(http.StatusForbidden)
		return
	} else {
		hash, err := bcrypt.GenerateFromPassword([]byte(masterkey[0]), BCRYPT_COST)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		data[MASTERKEY_FIELD] = string(hash)
		err = WriteSave(data)

		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		OpenSession(w, masterkey[0])
		http.Redirect(w, r, "/", http.StatusSeeOther)
	}
}

func ApiLogin(w http.ResponseWriter, r *http.Request) {
	err := r.ParseForm()
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	masterkey, ok := r.Form["masterkey"]
	if !ok {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	data, err := OpenSave()
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	if hash, ok := data[MASTERKEY_FIELD]; ok {
		if bcrypt.CompareHashAndPassword([]byte(fmt.Sprintf("%v", hash)), []byte(masterkey[0])) == nil {
			OpenSession(w, masterkey[0])
			http.Redirect(w, r, "/", http.StatusSeeOther)
		} else {
			w.WriteHeader(http.StatusForbidden)
		}
	} else {
		w.WriteHeader(http.StatusForbidden)
	}
}

func ApiEdit(w http.ResponseWriter, r *http.Request) {
	c, err := r.Cookie("session")
	if err != nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	masterkey, ok := SessionPassword(c.Value)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	data, err := OpenSave()
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	if hash, ok := data[MASTERKEY_FIELD]; ok {
		if bcrypt.CompareHashAndPassword([]byte(fmt.Sprintf("%v", hash)), masterkey) == nil {
			err = r.ParseForm()
			if err != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}

			service, ok := r.Form["service"]
			if !ok {
				w.WriteHeader(http.StatusBadRequest)
				return
			}

			username, ok := r.Form["username"]
			if !ok {
				w.WriteHeader(http.StatusBadRequest)
				return
			}

			password, ok := r.Form["password"]
			if !ok {
				w.WriteHeader(http.StatusBadRequest)
				return
			}

			key := sha256.Sum256(masterkey)
			cipher, err := aes.NewCipher(key[:])
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}

			padded, err := pkcs7pad([]byte(password[0]), cipher.BlockSize())
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}

			encrypted := make([]byte, len(padded))
			cipher.Encrypt(encrypted, padded)

			data[service[0]] = map[string]interface{}{"username": username[0], "password": base64.StdEncoding.EncodeToString(encrypted)}

			err = WriteSave(data)
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}

			http.Redirect(w, r, "/", http.StatusSeeOther)
		} else {
			w.WriteHeader(http.StatusForbidden)
		}
	} else {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
	}
}
