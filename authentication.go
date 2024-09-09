package main

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v4"
)

var config Config
var tokens []string
var (
	_, b, _, _ = runtime.Caller(0)
	basepath   = filepath.Dir(b)
)
var IPWhitelist = map[string]bool{
	"127.0.0.1":      true,
	"188.100.243.67": true,
	"138.246.0.0":    true,
	"131.159.0.0":    true,
	"88.77.0.0":      true,
	"178.1.0.0":      true,
}

type IpWhiteList struct {
	IPs []string `json:"ips"`
}

type Claims struct {
	Id       int    `json:"id"`
	Username string `json:"username"`
	jwt.RegisteredClaims
}

type JWTSecretFile struct {
	Secret     string
	ValidUntil time.Time
}

// ------------------------------------------------------------
// Setup and configuration
// ------------------------------------------------------------

func Setup(cfg Config) {
	config = cfg
	if ips, err := readIpWhitelistFromFile(); err != nil {
		log.Printf("Failed to read ips from disk: %s", err)
	} else if len(ips) > 0 {
		IPWhitelist = ips
	}
	if tkns, err := readTokensFromDisk(); err != nil {
		log.Printf("Failed to read tokens from disk: %s", err)
	} else {
		validTokens, err := removeInvalidTokens(tkns)
		if err != nil {
			log.Printf("Tokens invalid")
			return
		}
		tokens = validTokens
		storeTokensToDisk(true)
	}
}

func readIpWhitelistFromFile() (map[string]bool, error) {
	finalTokenPath := filepath.Join(basepath, "../../resources/whitelisted_ips.json")
	content, err := os.ReadFile(finalTokenPath)
	if err != nil {
		return nil, err
	}
	var ips IpWhiteList
	if err = json.Unmarshal(content, &ips); err != nil {
		return nil, err
	}
	log.Printf("Found IP Whitelist with %d IPs", len(ips.IPs))
	whiteIps := make(map[string]bool, len(ips.IPs))
	for _, ip := range ips.IPs {
		whiteIps[ip] = true
	}
	return whiteIps, nil
}

func storeTokensToDisk(overwrite bool) error {
	// Dont overwrite if already existing
	finalTokenPath := filepath.Join(basepath, "../../resources/tokens.txt")

	exists := true
	if _, err := os.Stat(finalTokenPath); errors.Is(err, os.ErrNotExist) {
		exists = false
	}
	fileMode := os.O_CREATE | os.O_WRONLY
	if overwrite {
		fileMode = fileMode | os.O_TRUNC
	} else {
		fileMode = fileMode | os.O_APPEND
	}
	file, err := os.OpenFile(finalTokenPath, fileMode, 0660)
	if err != nil {
		return err
	}
	for i, token := range tokens {
		if i == 0 && !exists { // Only use this mode for the very first token written to the file
			_, err := file.Write([]byte(token))
			if err != nil {
				return err
			}
			continue
		}
		_, err := file.Write([]byte("," + token))
		if err != nil {
			return err
		}
	}
	return nil
}

func removeInvalidTokens(tokens []string) ([]string, error) {
	claims := Claims{}
	var validTokens []string
	for _, token := range tokens {
		_, err := jwt.ParseWithClaims(token, &claims, func(t *jwt.Token) (interface{}, error) {
			_, ok := t.Method.(*jwt.SigningMethodHMAC)
			if !ok {
				return nil, errors.New("unauthorized")
			}
			pwd, _ := os.Getwd()
			finalJWTFile := filepath.Join(pwd, config.JWTSecretFile)
			data, err := os.ReadFile(finalJWTFile)
			if err != nil {
				log.Print("Failed to find JWT secret file")
				return nil, err
			}
			var jwtSecret JWTSecretFile
			if err = json.Unmarshal(data, &jwtSecret); err != nil {
				log.Print("JWT secret file is in incorrect format")
				return nil, err
			}
			if time.Now().After(jwtSecret.ValidUntil) {
				log.Print("The given secret is no longer valid! Please renew the secret")
				return nil, errors.New("token no longer valid")
			}
			secretKeyByte := []byte(jwtSecret.Secret)
			return secretKeyByte, nil
		})
		if err != nil {
			// log.Printf("Token no longer valid? %s", err)
			continue
		}
		validTokens = append(validTokens, token)
	}
	log.Printf("Removed %d tokens", len(tokens)-len(validTokens))
	return validTokens, nil
}

func readTokensFromDisk() ([]string, error) {
	finalTokenPath := filepath.Join(basepath, "../../resources/tokens.txt")
	content, err := os.ReadFile(finalTokenPath)
	if err != nil {
		return nil, err
	}
	readTokens := strings.Split(string(content), ",")
	log.Printf("Read %d tokens from disk", len(readTokens))
	return readTokens, nil
}

func checkJWTTokenIssued(token string) error {
	storedTokens, err := readTokensFromDisk()
	if err != nil {
		return errors.New("no stored tokens found")
	}
	allTokens := append(storedTokens, tokens...)
	for _, storedTkn := range allTokens {
		if storedTkn == token {
			return nil
		}
	}
	return errors.New("token not found")
}

func AuthenticationMiddleware(cfg Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		// body, _ := io.ReadAll(c.Request.Body)
		// header := c.Request.Header
		origin := c.ClientIP()
		remote := c.RemoteIP()
		// log.Printf("Request body: %s", body)
		// log.Printf("Request header: %s", header)
		log.Printf("Origin: %s, Remote: %s", origin, remote)

		// TODO: Add the API token-
		tokenString := c.GetHeader("Authorization")
		if tokenString == "" {
			log.Print("No token found! Abort")
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "no token"})
			return
		}
		splits := strings.Split(tokenString, " ")
		if len(splits) != 2 {
			log.Printf("Token in incorrect format! '%s'", tokenString)
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "wrong token format"})
			return
		}
		reqToken := splits[1]
		claims := Claims{}
		token, err := jwt.ParseWithClaims(reqToken, &claims, func(t *jwt.Token) (interface{}, error) {
			_, ok := t.Method.(*jwt.SigningMethodHMAC)
			if !ok {
				return nil, errors.New("unauthorized")
			}
			// parsedClaim, ok := t.Claims.(Claims)
			// if !ok {
			// 	log.Print("Token in invalid format")
			// 	return nil, errors.New("token in invalid format")
			// }
			// log.Printf("Token is issued for: %d", parsedClaim.Id)
			pwd, _ := os.Getwd()
			finalJWTFile := filepath.Join(pwd, config.JWTSecretFile)
			data, err := os.ReadFile(finalJWTFile)
			if err != nil {
				log.Print("Failed to find JWT secret file")
				return nil, err
			}
			var jwtSecret JWTSecretFile
			err = json.Unmarshal(data, &jwtSecret)
			if err != nil {
				log.Print("JWT secret file is in incorrect format")
				return nil, err
			}
			if time.Now().After(jwtSecret.ValidUntil) {
				log.Print("The given secret is no longer valid! Please renew the secret")
				return nil, errors.New("token no longer valid")
			}
			secretKeyByte := []byte(jwtSecret.Secret)
			return secretKeyByte, nil
		})
		// log.Printf("Parsing got: %s, %s", token.Raw, err)
		if err != nil {
			log.Printf("Error during token parsing: %s", err)
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid token"})
			return
		}
		// Checking if user in this form exists
		// TODO: Find a way to extract the custom information from the token
		// parsedClaims, ok := token.Claims.(*Claims)
		// if !ok {
		// 	log.Print("Received token claims are in incorrect format!")
		// 	c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid token"})
		// 	return
		// }
		// user, err := database.GetUser(int64(parsedClaims.Id))
		// if err != nil {
		// 	log.Printf("User for id %d not found!", parsedClaims.Id)
		// 	c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid token"})
		// 	return
		// }
		// if user.Username != parsedClaims.Username {
		// 	log.Print("The stored user and claimed token user do not match")
		// 	c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid token"})
		// 	return
		// }
		// Check if the token was issued
		if err = checkJWTTokenIssued(reqToken); err != nil {
			log.Printf("Error with token: %s", err)
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid token"})
			return
		}
		if token.Valid {
			c.Set("userId", int64(claims.Id))
			c.Next()
		} else {
			log.Printf("Invalid claims: %s", claims.Valid().Error())
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid token"})
		}
	}
}
