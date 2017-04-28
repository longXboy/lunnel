# netbug

[![GoDoc](https://godoc.org/github.com/e-dard/netbug?status.svg)](https://godoc.org/github.com/e-dard/netbug)

Package `netbug` provides access to an `http.Handler` that accesses the profiling and debug tools available in the `/net/http/pprof` and `/runtime/pprof` packages.

The advantages of using `netbug` over the existing `/net/http/pprof` handlers are:

 1. You can register the handler under an arbitrary route-prefix. A use-case might be to have a secret endpoint for keeping this information hidden from prying eyes, rather than `/debug/pprof`;
 2. It pulls together all the handlers from `/net/http/pprof` *and* `/runtime/pprof` into a single index page, for when you can't quite remember the URL for the profile you want;
 3. You can register the handlers onto `http.ServeMux`'s that aren't `http.DefaultServeMux`;
 4. It provides an optional handler that requires a token URL parameter. This is useful if you want that little bit of extra security (use this over HTTPS connections only).

**Note**:
It still imports `/net/http/pprof`, which means the `/debug/pprof` routes in that package *still* get registered on `http.DefaultServeMux`.
If you're using this package to avoid those routes being registered, you should use it with your *own* `http.ServeMux`.

`netbug` is trying to cater for the situation where you want all profiling tools available remotely on your running services, but you don't want to expose the `/debug/pprof` routes that `net/http/pprof` forces you to expose.

## How do I use it?
In the simplest case give `netbug` the `http.ServeMux` you want to register the handlers on, as well as where you want to register the handler and you're away.

```go
package main

import (
	"log"
	"net/http"

	"github.com/e-dard/netbug"
)

func main() {
	r := http.NewServeMux()
	netbug.RegisterHandler("/myroute/", r)
	if err := http.ListenAndServe(":8080", r); err != nil {
		log.Fatal(err)
	}
}
```

Visiting [http://localhost:8080/myroute/](http://localhost:8080/myroute/) will then return:

![](https://photos-3.dropbox.com/t/2/AABdAn1yRTBvqXeDJygtCRsMu1HMqTohoIJdWAQ7vH_j_g/12/5033766/png/32x32/1/1446145200/0/2/Screen%20Shot%202015-10-29%20at%2017.01.45.png/CKaeswIgASACIAMgBSAHKAEoAigH/vaSYDZEeuTA-8biklDyYORywwvL9SbVYH41Jff_CuBk?size_mode=5)

`netbug` also provides a simple way of adding some authentication:

```go
package main

import (
	"log"
	"net/http"

	"github.com/e-dard/netbug"
)

func main() {
	r := http.NewServeMux()
	netbug.RegisterAuthHandler("password", "/myroute/", r)
	if err := http.ListenAndServe(":8080", r); err != nil {
		log.Fatal(err)
	}
}
```

And visit [http://localhost:8080/myroute/?token=password](http://localhost:8080/myroute/?token=password).

**Obviously** this form of authentication is pointless if you're not accessing the routes over an HTTPS connection.
If you want to use a different form of authentication, e.g., HTTP Basic Authentication, then you can use the handler returned by `netbug.Handler()`, and wrap it with handlers provided by packages like [github.com/abbot/go-http-auth](https://github.com/abbot/go-http-auth/).

### What can you do with it?

It just wraps the behaviour of the [/net/http/pprof](http://golang.org/pkg/net/http/pprof/) and [/runtime/pprof](http://golang.org/pkg/runtime/pprof/) packages.
Check out their documentation to see what's available.
As an example though, if you want to run a 30-second CPU profile on your running service it's really simple:

```
$ go tool pprof https://example.com/myroute/profile
```

##### New in Go 1.5
You can now produce [execution traces](https://golang.org/pkg/runtime/trace/) of your remotely running program using netbug.

To do this run one of the trace profiles, which will result in a file being downloaded. Then use the Go `trace` tool to generate a trace, which will open up in your browser.

```
$ go tool trace binary-being-profiled /path/to/downloaded/trace
```

When compiling `binary-being-profiled`, you will need to have targeted the same architecture as the binary that generated the profile.

## Background
The [net/http/pprof](http://golang.org/pkg/net/http/pprof/) package is great.
It let's you access profiling and debug information about your running services, via `HTTP`, and even plugs straight into `go tool pprof`.
You can find out more about using the `net/http/pprof` package at the bottom of [this blog post](http://blog.golang.org/profiling-go-programs).

However, there are a couple of problems with the `net/http/pprof` package.

 1. It assumes you're cool about the relevant handlers being registered under the `/debug/pprof` route.
 2. It assumes you're cool about handlers being registered on `http.DefaultServeMux`.
 3. You can't wrap the handlers in any way, say to add authentication or other logic.

You can sort of fix (1) and (2) by digging around the `net/http/pprof` package and registering all all the exported handlers under different paths on your own `http.ServeMux`, but you still have the problem of the index page—which is useful to visit if you don't profile much—using hard-coded paths.
It doesn't really work well.
Also, the index page doesn't provide you with easy links to the debug information that the `net/http/pprof` package has handlers for.

`netbug` is just a small package to fix these issues.

