// Package netbug provides an http.Handler for executing the various
// profilers and debug tools in the Go standard library.
//
// netbug provides some advantages over the /net/http/pprof and
// /runtime/pprof packages:
//
//	1. You can register the handler under an arbitrary route or with
//	   some authentication on the handler, making it easier to to keep
//	   the profilers and debug information away from prying eyes;
//	2. It pulls together all the handlers from /net/http/pprof and
//	   runtime/pprof into a single index page, for when you can't
//	   quite remember the URL for the profile you want; and
//	3. You can register the handler onto an `http.ServeMux` that
//	   isn't `http.DefaultServeMux`.
//
//
// The simplest integration of netbug looks like:
//
//	package main
//
//	import (
//		"log"
//		"net/http"
//
//		"github.com/e-dard/netbug"
//	)
//
//	func main() {
//		r := http.NewServeMux()
//		netbug.Register("/myroute/", r)
//
//		if err := http.ListenAndServe(":8080", r); err != nil {
//			log.Fatal(err)
//		}
//	}
//
// You can then access the index page via GET /myroute/
//
// The netbug.RegisterAuthHandler function lets you register the handler on
// your http.ServeMux and add some simple authentication, in the
// form of a URL parameter:
//
//	package main
//
//	import (
//		"log"
//		"net/http"
//
//		"github.com/e-dard/netbug"
//	)
//
//	func main() {
//		r := http.NewServeMux()
//		netbug.RegisterAuthHandler("open sesame", "/myroute/", r)
//
//		if err := http.ListenAndServe(":8080", r); err != nil {
//			log.Fatal(err)
//		}
//	}
//
// You can then access the index page via:
//
// 	GET /myroute/?token=open%20sesame
//
// The package also provides access to the handlers directly, for when
// you want to, say, wrap them in your own logic. Just be sure that
// when you use the handlers that netbug provides, you take care to use
// `http.StripPrefix` to strip the route you registered the handler on.
// This is because the handlers' logic expect them to be registered on
// "/".
//
//	package main
//
//	import (
//		"log"
//		"net/http"
//
//		"github.com/e-dard/netbug"
//	)
//
//	// h is a handler that you wish to wrap around netbug's handler,
//	// allowing you to add your own logic (other types of
//	// authentication for example).
// 	func h(h http.Handler) http.Handler {
//		mh := func(w http.ResponseWriter, r *http.Request) {
//			// Some logic here.
//			h.ServeHTTP(w, r)
//		}
//		return http.HandlerFunc(mh)
//	}
//
//	func main() {
//		r := http.NewServeMux()
//
//		// netbug's handler assumes it's registered on "/", so you need
//		// to strip any prefix you actually want to register it on, if
//		// you're not using the netbug.RegisterX functions.
//		nbH := http.StripPrefix("/myroute/", netbug.Handler())
//
//		// Wrap the netbug handler in your own, and register the result.
//		r.Handle("/myroute/", h(nbH))
//
//		if err := http.ListenAndServe(":8080", r); err != nil {
//			log.Fatal(err)
//		}
//	}
//
// As you would expect, netbug works the same way with the go profiler
// tool as /net/http/pprof does. To run a 30 second CPU profile on your
// service for example:
//
//	$ go tool pprof https://example.com/myroute/profile
//
package netbug
