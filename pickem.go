package main

import (
    "net/http"
    "github.com/gorilla/context"
    "github.com/gorilla/mux"
    "gopkg.in/unrolled/render.v1"
    "github.com/codegangsta/negroni"
)

func main() {



    router := mux.NewRouter().StrictSlash(false)
    router.HandleFunc("/", HomeHandler)

    // Log In/Out Routes
    auth := router.PathPrefix("/auth").Subrouter()
    auth.Path("/login").Methods("POST").HandlerFunc(LoginPostHandler)
    auth.Path("/refresh").Methods("POST").HandlerFunc(RefreshPostHandler)
    auth.Path("/logout").Methods("POST").HandlerFunc(LogoutPostHandler)


    // I'm not a huge fan of it, but the Negroni middleware doesn't work fantastically
    // with Gorilla subrouters. So instead, the routes are set up in a bit more
    // long winded fashion to allow for wrapping some around the JWT middleware
    // Users collections
    users := mux.NewRouter().StrictSlash(false)
    users.Path("/users").Methods("POST").HandlerFunc(UsersPostHandler)
    users.Path("/users").Methods("GET").HandlerFunc(UsersIndexHandler)
    router.Path("/users").Handler(negroni.New(
            JwtMiddleware(),
            negroni.Wrap(users),
    ))

    user := mux.NewRouter().StrictSlash(false)
    user.Path("/users/{username}").Methods("GET").HandlerFunc(UserGetHandler)
    user.Path("/users/{username}").Methods("PUT").HandlerFunc(UserPutHandler)
    user.Path("/users/{username}").Methods("DELETE").HandlerFunc(UserDeleteHandler)
    router.Path("/users/{username}").Handler(negroni.New(
            JwtMiddleware(),
            negroni.Wrap(user),
    ))

    // Brackets Collection
    // Need full Bracket CRUD

    // Groups Collection
    // Need full Group CRUD

    // Set up the common middleware
    n := negroni.New(
        negroni.NewRecovery(),
        negroni.NewLogger(),
        MongoMiddleware(),
        JsonParserMiddleware(),
    )
    n.UseHandler(context.ClearHandler(router))

    n.Run(":8080")
}

func HomeHandler(rw http.ResponseWriter, r *http.Request) {
    rend := render.New(render.Options{})
    rend.JSON(rw, http.StatusOK, map[string]string{"hello": "world"})
}

