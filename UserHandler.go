package main

import (
	"fmt"
	valid "github.com/gima/govalid/v1"
	"github.com/gorilla/mux"
	"golang.org/x/crypto/bcrypt"
	"gopkg.in/mgo.v2"
	"gopkg.in/mgo.v2/bson"
	"gopkg.in/unrolled/render.v1"
	"log"
	"net/http"
	"strings"
)

// Our user models works under the assumption that the username has a unique
// index in our database.
// db.user.createIndex( { "username": 1 }, { unique: true } )

// UsersPostHandler is a Gorilla handler that accepts a JSON post of data and
// creates a new user based off of the data. The needed fields are:
// - username
// - firstName
// - lastName
// - password
// - confirmPassword
func UsersPostHandler(rw http.ResponseWriter, req *http.Request) {
	inputMap := GetJson(req)
	db := GetDb(req)
	rend := render.New(render.Options{})

	// Validate the request coming in
	schema :=
		valid.Object(
			valid.ObjKV("username", valid.String(valid.StrMin(1))),
			valid.ObjKV("firstName", valid.String(valid.StrMin(1))),
			valid.ObjKV("lastName", valid.String(valid.StrMin(1))),
			valid.ObjKV("password", valid.String(valid.StrMin(8))),
			valid.ObjKV("confirmPassword", valid.String(valid.StrMin(8))),
		)
	if path, err := schema.Validate(&inputMap); err != nil {
		log.Println("[ERROR] Failed (", err, "). Path:", path)
		rend.JSON(rw, http.StatusBadRequest, map[string]interface{}{
			"errorStatus":  400,
			"errorMessage": fmt.Sprintf("Failed (%s). Path: %s", err, path)})
		return
	}

	// Make sure the two password inputs matched
	if inputMap["password"] != inputMap["confirmPassword"] {
		log.Println("[ERROR] Password and Confirmation did not match")
		rend.JSON(rw, http.StatusBadRequest, map[string]interface{}{
			"errorStatus":  400,
			"errorMessage": "Password and Confirmation did not match"})
		return
	}

	// Hash the password before storing it
	password := inputMap["password"].(string)
	passwordSlice := []byte(password)
	hashedPassword, hashErr := bcrypt.GenerateFromPassword(passwordSlice, 10)
	if hashErr != nil {
		log.Printf("Error hashing password: %s", hashErr)
		rw.WriteHeader(500)
		return
	}

	// For data integrity, explicitly set the structure of the data
	// to be persisted. This one, no one inserts data that should not be there
	insertUser := map[string]interface{}{
		"firstName": inputMap["firstName"].(string),
		"lastName":  inputMap["lastName"].(string),
		"username":  inputMap["username"].(string),
		"password":  hashedPassword,
	}

	// Persist the data into the database
	if err := db.C("user").Insert(insertUser); err != nil {
		if strings.Contains(err.Error(), "E11000") {
			log.Println("[ERROR] Password and Confirmation did not match")
			rend.JSON(rw, http.StatusBadRequest, map[string]interface{}{
				"errorStatus":  400,
				"errorMessage": "Username is already in use"})
			return
		}
		log.Println("Error was from database: ", err)
		rw.WriteHeader(500)
		return
	}

	rend.JSON(rw, http.StatusOK, map[string]bool{"success": true})
}

// UserPutHandler is a Gorilla handler that accepts JSON post data to update
// an already existing user. It enforces that a user is only allowed to update
// their own information. Values that can be updated are:
// - username
// - firstName
// - lastName
func UserPutHandler(rw http.ResponseWriter, req *http.Request) {
	inputMap := GetJson(req)
	authUser := GetUser(req)
	db := GetDb(req)
	rend := render.New(render.Options{})

	// Get the query parameters so that I know which user to update
	requestUsername := mux.Vars(req)["username"]

	// Only allow users to update themselves
	if authUser["username"] != requestUsername {
		rend.JSON(rw, http.StatusForbidden, bson.M{
			"errorStatus":  403,
			"errorMessage": "Not allowed to update other users"})
		return
	}

	// Validate the request coming in
	schema :=
		valid.Object(
			valid.ObjKV("username", valid.Optional(valid.String(valid.StrMin(1)))),
			valid.ObjKV("firstName", valid.Optional(valid.String(valid.StrMin(1)))),
			valid.ObjKV("lastName", valid.Optional(valid.String(valid.StrMin(1)))),
		)
	if path, err := schema.Validate(&inputMap); err != nil {
		log.Println("[ERROR] Failed (", err, "). Path:", path)
		rend.JSON(rw, http.StatusBadRequest, map[string]interface{}{
			"errorStatus":  400,
			"errorMessage": fmt.Sprintf("Failed (%s). Path: %s", err, path)})
		return
	}

	// For data integrity, explicitly set the structure of the data
	// to be persisted. This way, no one inserts data that should not be there
	updatableKeys := []string{"firstName", "lastName", "username"}
	var updateUser bson.M
	for _, element := range updatableKeys {
		if inputMap[element] != nil {
			// All of the values in this case are strings, so this is simple
			updateUser[element] = inputMap[element].(string)
		}
	}
	userChange := mgo.Change{
		Update: bson.M{"$set": updateUser},
	}

	// Just update the provided values
	if _, err := db.C("user").Find(bson.M{"username": requestUsername}).Apply(userChange, &bson.M{}); err != nil {
		if strings.Contains(err.Error(), "E11000") {
			log.Println("[ERROR] Username already taken")
			rend.JSON(rw, http.StatusBadRequest, bson.M{
				"errorStatus":  400,
				"errorMessage": "Username is already in use"})
			return
		}
		log.Println("Error was from database: ", err)
		rw.WriteHeader(500)
		return
	}

	rend.JSON(rw, http.StatusOK, map[string]bool{"success": true})
}

// UserGetHandler is a Gorilla handler that uses the username query parameter
// to find the non-sensitive data for a user and return it in a JSON API
func UserGetHandler(rw http.ResponseWriter, req *http.Request) {
	db := GetDb(req)
	// Get the query parameters so that I know which user to update
	requestUsername := mux.Vars(req)["username"]
	rend := render.New(render.Options{})

	user := bson.M{}

	// Fetch users
	if err := db.C("user").Find(bson.M{"username": requestUsername}).Select(bson.M{"password": 0}).One(&user); err != nil {
		rend.JSON(rw, http.StatusNotFound, map[string]interface{}{
			"errorStatus":  404,
			"errorMessage": "User not found"})
		return
	}

	rend.JSON(rw, http.StatusOK, user)
}

// UserDeleteHandler is a Gorilla handler that uses the username query paramter
// to find a user and remove them from the system. The handler enforces the
// logic that a user can only remove themselves from the system.
func UserDeleteHandler(rw http.ResponseWriter, req *http.Request) {
	db := GetDb(req)
	authUser := GetUser(req)
	// Get the query parameters so that I know which user to update
	requestUsername := mux.Vars(req)["username"]
	rend := render.New(render.Options{})

	// Only allow users to update themselves
	if authUser["username"] != requestUsername {
		rend.JSON(rw, http.StatusForbidden, bson.M{
			"errorStatus":  403,
			"errorMessage": "Not allowed to delete other users"})
		return
	}

	userChange := mgo.Change{
		Remove: true,
	}

	if _, err := db.C("user").Find(bson.M{"username": requestUsername}).Apply(userChange, &bson.M{}); err != nil {
		log.Println("Error was from database: ", err)
		if err.Error() == "not found" {
			rend.JSON(rw, http.StatusNotFound, bson.M{
				"errorStatus":  404,
				"errorMessage": "User was not found"})
			return
		}
		rend.JSON(rw, http.StatusInternalServerError, bson.M{
			"errorStatus":  500,
			"errorMessage": "Unable to delete user"})
		return
	}
}

// UsersIndexHandler is a Gorilla handler that returns the non-sensitive data
// for all users in the system.
func UsersIndexHandler(rw http.ResponseWriter, req *http.Request) {
	// Get the database connection
	db := GetDb(req)
	// Empty array of interfaces for our users. We won't use the
	// User model in this case, because we want to be able to ignore
	// the password altogether
	users := []interface{}{}

	// Fetch users
	if err := db.C("user").Find(nil).Select(bson.M{"password": 0}).All(&users); err != nil {
		rw.WriteHeader(404)
		return
	}

	rend := render.New(render.Options{})
	rend.JSON(rw, http.StatusOK, users)
}
