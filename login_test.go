package main

import (
	"testing"
	"github.com/beewit/beekit/utils/uhttp"
	"github.com/beewit/sso/global"
	"encoding/json"
	"github.com/beewit/beekit/utils"
)

func TestLogin(t *testing.T) {
	b, err := uhttp.PostForm("http://127.0.0.1:8081/pass/checkToken?token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.K2EF3z2H820vBIjrsduiIXVJQ6A-26qmib4QlcqCzgs", nil)
	if err != nil {
		global.Log.Error(err.Error())
		t.Error(err)
	}
	println(string(b[:]))
	var rp utils.ResultParam
	json.Unmarshal(b[:], &rp)
	println("牛逼了")
}
