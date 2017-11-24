package main

import (
	"testing"
	"github.com/beewit/beekit/utils/uhttp"
	"github.com/beewit/sso/global"
	"encoding/json"
	"github.com/beewit/beekit/utils"
	"github.com/beewit/sso/handler"
	"github.com/labstack/echo"
	"net/http/httptest"
	"strings"
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

func TestString2Map(t *testing.T) {
	str := `{"errcode":40029,"errmsg":"invalid code, hints: [ req_id: 0C0mGA0824th31 ]"}`
	b := strings.Contains(str, "errcode")

	t.Log(b)
}

func TestWechatLogin(t *testing.T) {
	userJSON := `{"code" :"081u2W2g1xQWZw0Ggu1g1fVW2g1u2W2c"}`
	e := echo.New()
	req := httptest.NewRequest("POST", "/union/weixin/code?code=081ENjg92WLp2P0hL7d924ang92ENjgS", strings.NewReader(userJSON))
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec).(echo.Context)
	t.Log(handler.WechatCode(c))
}

func TestRandStr(t *testing.T) {
	println(handler.GetRand())
}
