package main

import (
	"encoding/json"
	"github.com/beewit/beekit/utils"
	"github.com/beewit/beekit/utils/uhttp"
	"github.com/beewit/sso/global"
	"github.com/beewit/sso/handler"
	"github.com/labstack/echo"
	"github.com/stretchr/testify/assert"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
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

func TestBindOrRegisterWechatMiniApi(t *testing.T) {
	e := echo.New()
	f := url.Values{}
	f.Set("mobile", "18223277005")
	f.Set("smsCode", "5694")
	f.Set("userinfo", `{"nickName":"承诺，一时的华丽","gender":1,"language":"zh_CN","city":"Shapingba","province":"Chongqing","country":"China","avatarUrl":"https://wx.qlogo.cn/mmopen/vi_32/Q0j4TwGTfTKw8ictgYcqf6uklrSAup13EoCQ2SyfASGwOkOicAFibBz7LVgyPm7DoMPDhcqzNZzgXsJWt3r1l9gxQ/0"}`)
	f.Set("session_id", `{"openid":"123456","session_key","0000000","unionid":"oWYCdv-DoLpnOHjx3gnPSIA3tvaU"}`)
	f.Set("pwd", "123456")
	req := httptest.NewRequest(echo.POST, "/", strings.NewReader(f.Encode()))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationForm)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	// 断言
	if assert.NoError(t, handler.BindOrRegisterWechatMiniApi(c)) {
		assert.Equal(t, http.StatusOK, rec.Code)
		t.Error(rec.Body.String())
	}
}

func TestGetWechatMiniUnionID(t *testing.T) {
	e := echo.New()
	f := url.Values{}
	f.Set("code", "003AFO9I1jNj680Vw06I1JeG9I1AFO9N")
	req := httptest.NewRequest(echo.POST, "/", strings.NewReader(f.Encode()))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationForm)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	// 断言
	if assert.NoError(t, handler.WechatMiniUnionIDLogin(c)) {
		assert.Equal(t, http.StatusOK, rec.Code)
		t.Error(rec.Body.String())
	}
}
