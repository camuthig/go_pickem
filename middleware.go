package main

import (
    "log"
    "os"
    "net/http"
    "github.com/gorilla/context"
    "github.com/codegangsta/negroni"
    "gopkg.in/mgo.v2"
    "encoding/json"
    "gopkg.in/dgrijalva/jwt-go.v2"
    "github.com/camuthig/go-jwt-middleware"
)

const db = 0
const jsonMap = 0

func GetDb(r *http.Request) *mgo.Database {
    if rv := context.Get(r, "db"); rv != nil {
        return rv.(*mgo.Database)
    }
    return nil
}

func SetDb(r *http.Request, val *mgo.Database) {
    context.Set(r, "db", val)
}

func GetUser(r *http.Request) map[string]interface{} {
    if rv := context.Get(r, "user"); rv != nil {
        userMap := rv.(*jwt.Token)
        if userMap != nil {
            return userMap.Claims["user"].(map[string]interface{})
        }
    }
    return nil
}

func GetJson(r *http.Request) map[string]interface{} {
    if rv := context.Get(r, "jsonMap"); rv != nil {
        return rv.(map[string]interface{})
    }
    return nil
}

func SetJson(r *http.Request, val interface{}) {
    // Convert the interface to a map so that I have access to the variables in it
    inputMap := val.(map[string]interface{})
    context.Set(r, "jsonMap", inputMap)
}

// MongoMiddleware creates a Negroni middleware function that handles the logic
// of building and closing a connection to our MongoDB database and adding
// it to the request context. The code is taken
// from this gist: https://gist.github.com/Bochenski/253dbc8c077599d234c3
func MongoMiddleware() negroni.HandlerFunc {
    session, err := mgo.Dial("mongodb://localhost")

    if err != nil {
        panic(err)
    }

    return negroni.HandlerFunc(func(rw http.ResponseWriter, r *http.Request, next http.HandlerFunc) {
        reqSession := session.Clone()
        defer reqSession.Close()
        db := reqSession.DB("pickem")
        SetDb(r, db)
        next(rw, r)
    })
}

// JsonParserMiddleware creates a Negroni handler that will parse the JSON body
// of a POST or PUT request and put it into an interface.
func JsonParserMiddleware() negroni.HandlerFunc {
    return negroni.HandlerFunc(func(rw http.ResponseWriter, req *http.Request, next http.HandlerFunc) {
        if req.Method == "POST" || req.Method == "PUT" {
            var jsonInput interface{}
            err := json.NewDecoder(req.Body).Decode(&jsonInput)
            if err != nil {
               // handle error
            }
            SetJson(req, jsonInput)
        }
        next(rw, req)
    })
}

func TestMiddleware() negroni.HandlerFunc {
    return negroni.HandlerFunc(func(rw http.ResponseWriter, req *http.Request, next http.HandlerFunc) {
        log.Println("Testing the user only route middleware")
        next(rw, req)
    })
}

func JwtMiddleware() negroni.HandlerFunc {
    jwtHandler := jwtmiddleware.New(jwtmiddleware.Options{
        ValidationKeyGetter: func(token *jwt.Token) (interface{}, error) {
            return []byte(os.Getenv("AUTH0_CLIENT_SECRET")), nil
        },
    })

    return jwtHandler.HandlerWithNext
}
