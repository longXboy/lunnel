package main

import (
	"fmt"
	"net/http"
)

func handler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w,
		"Hi, This is an example of https service in golang!")
}

func main() {
	http.HandleFunc("/", handler)
	err := http.ListenAndServeTLS(":8081", "ec.crt",
		"ec.uncrypted.pem", nil)
	fmt.Println(err)
}
