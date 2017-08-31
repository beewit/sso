package main

import (
	"runtime"
	"github.com/beewit/sso/router"
)

func main() {
	runtime.GOMAXPROCS(runtime.NumCPU())
	router.Start()
}
