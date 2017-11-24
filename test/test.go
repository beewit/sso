package main

import (
	"github.com/beewit/beekit/utils"
)

func main() {
	iw, _ := utils.NewIdWorker(1)
	for i := 0; i < 20; i++ {
		go func() {
			id, _:= iw.NextId()
			println(id)
		}()
	}
}
