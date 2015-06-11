package main

import (
	"crypto/rand"
	"encoding/base64"
	"golang.org/x/crypto/bcrypt"
	"gopkg.in/dgrijalva/jwt-go.v2"
	"gopkg.in/mgo.v2"
	"gopkg.in/mgo.v2/bson"
	"gopkg.in/unrolled/render.v1"
	"log"
	"net/http"
	"os"
	"time"
)

func createJwtToken(user bson.M) (token string, err interface{}) {
	// Create a new token
	jwtToken := jwt.New(jwt.SigningMethodHS256)
	// Set some claims
	jwtToken.Claims["user"] = user
	jwtToken.Claims["exp"] = time.Now().Add(time.Hour * 72).Unix()
	// Sign and get the complete encoded token as a string
	jwtString, jwtErr := jwtToken.SignedString([]byte(os.Getenv("AUTH0_CLIENT_SECRET")))

	if jwtErr != nil {
		log.Println("Error creating the JWT:", jwtErr)
	}

	return jwtString, jwtErr

}

func LoginPostHandler(rw http.ResponseWriter, req *http.Request) {
	inputMap := GetJson(req)
	db := GetDb(req)
	rend := render.New(render.Options{})

	user := bson.M{}
	// Fetch the user by user name
	if err := db.C("user").Find(map[string]interface{}{"username": inputMap["username"].(string)}).One(&user); err != nil {
		rend.JSON(rw, http.StatusForbidden, bson.M{})
		return
	}

	inputPassword := inputMap["password"].(string)
	inputPasswordSlice := []byte(inputPassword)
	passwordCheck := bcrypt.CompareHashAndPassword(user["password"].([]byte), inputPasswordSlice)

	// Clean out the password now so that we can pass the data in the JWT
	delete(user, "password")

	if passwordCheck == nil {
		// Create a JWT
		jwtString, err := createJwtToken(user)
		if err != nil {
			rend.JSON(rw, http.StatusInternalServerError, bson.M{})
			return
		}

		// Create the User Refresh Token and persist it
		size := 64 // change the length of the generated random string here
		rb := make([]byte, size)
		if _, randomErr := rand.Read(rb); randomErr != nil {
			log.Println("Error creating the refresh token:", err)
			rend.JSON(rw, http.StatusInternalServerError, bson.M{})
			return
		}
		refreshToken := base64.URLEncoding.EncodeToString(rb)

		if tokenInsertErr := db.C("refreshtoken").Insert(bson.M{"user": user["_id"], "refreshToken": refreshToken}); tokenInsertErr != nil {
			rend.JSON(rw, http.StatusInternalServerError, bson.M{})
			return
		}

		rend.JSON(rw, http.StatusOK, bson.M{
			"jwt":          jwtString,
			"refreshToken": refreshToken,
		})
	} else {
		log.Printf("Passwords did not match: %s", passwordCheck)
		rend.JSON(rw, http.StatusForbidden, map[string]interface{}{})
	}
}

func LogoutPostHandler(rw http.ResponseWriter, req *http.Request) {
	db := GetDb(req)
	inputMap := GetJson(req)
	rend := render.New(render.Options{})

	// When we logout, the actual goal is to clear out the current JWT refresh token
	// The client-side should also discard the JWT itself. These two steps, along with a
	// short (shorter than current 72 hours) expiration would make it more secure
	tokenChange := mgo.Change{
		Remove: true,
	}

	if _, err := db.C("refreshtoken").Find(bson.M{"refreshToken": inputMap["refreshToken"].(string)}).Apply(tokenChange, &bson.M{}); err != nil {
		log.Println("Error was from database: ", err)
		if err.Error() == "not found" {
			rend.JSON(rw, http.StatusInternalServerError, bson.M{
				"errorStatus":  404,
				"errorMessage": "Unable to find and remove refresh token"})
		} else {
			rend.JSON(rw, http.StatusInternalServerError, bson.M{
				"errorStatus":  500,
				"errorMessage": "Unable to delete user"})
		}
	}
}

func RefreshPostHandler(rw http.ResponseWriter, req *http.Request) {
	db := GetDb(req)
	inputMap := GetJson(req)
	rend := render.New(render.Options{})

	// Find the refresh token to determine the user to go with it
	refreshToken := bson.M{}
	if err := db.C("refreshtoken").Find(bson.M{"refreshToken": inputMap["refreshToken"].(string)}).One(&refreshToken); err != nil {
		log.Println("[Error] Unable to find the refresh token:", err)
		rend.JSON(rw, http.StatusNotFound, bson.M{})
		return
	}

	// Fetch the user by the ID
	user := bson.M{}
	if err := db.C("user").Find(bson.M{"_id": refreshToken["user"].(bson.ObjectId)}).One(&user); err != nil {
		log.Println("[Error] Unable to find the user")
		rend.JSON(rw, http.StatusNotFound, bson.M{})
		return
	}

	jwtString, err := createJwtToken(user)
	if err != nil {
		rend.JSON(rw, http.StatusInternalServerError, bson.M{})
		return
	}

	rend.JSON(rw, http.StatusOK, bson.M{"jwt": jwtString})
}
