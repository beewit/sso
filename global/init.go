package global

import (
	"github.com/beewit/beekit/conf"
	"github.com/beewit/beekit/log"
	"github.com/beewit/beekit/mysql"
	"github.com/beewit/beekit/redis"
	"fmt"
	"github.com/beewit/beekit/utils/convert"
	"github.com/labstack/echo"
	"github.com/gorilla/sessions"
	"github.com/labstack/echo-contrib/session"
)

var (
	CFG  = conf.New("config.json")
	Log  = log.Logger
	DB   = mysql.DB
	RD   = redis.Cache
	IP   = CFG.Get("server.ip")
	Port = CFG.Get("server.port")
	Host = fmt.Sprintf("http://%v:%v", IP, Port)

	SmsGatewayUrl      = convert.ToString(CFG.Get("sms.gatewayUrl"))
	SmsAccessKeyId     = convert.ToString(CFG.Get("sms.accessKeyId"))
	SmsAccessKeySecret = convert.ToString(CFG.Get("sms.accessKeySecret"))
	SmsSignName        = convert.ToString(CFG.Get("sms.signName"))
	WeiboAppKey        = convert.ToString(CFG.Get("weibo.appKey"))
	WeiboAppSecret     = convert.ToString(CFG.Get("weibo.appSecret"))
	WeiboRedirectUri   = convert.ToString(CFG.Get("weibo.redirectUri"))
	WechatAppId        = convert.ToString(CFG.Get("wechat.appId"))
	WechatAppSecret    = convert.ToString(CFG.Get("wechat.appSecret"))
	WechatRedirectUri  = convert.ToString(CFG.Get("wechat.redirectUri"))

	LoginToken = func(mobile string) string { return fmt.Sprintf("%v_LOGIN_TOKEN", mobile) }

	Session = func(c echo.Context) *USession { return getSession(c) }
)

const (
	SMS_TEMPLATE_REG         = "SMS_83430283"
	SMS_TEMPLATE_PARAM       = "{\"code\":\"%v\"}"
	IMG_CODE                 = "imgCodeRedis"
	IMG_CODE_EXPIRE    int64 = 60
	SMS_CODE_EXPIRE    int64 = 10 * 60
)

func getSession(c echo.Context) *USession {
	ses, _ := session.Get("Go_Session_Id", c)
	ses.Options = &sessions.Options{
		Path:     "/",
		MaxAge:   60 * 20,
		HttpOnly: true,
	}

	return &USession{
		ses,
		c,
	}
}

type USession struct {
	*sessions.Session
	echo.Context
}

func (us *USession) Saves() {
	us.Save(us.Context.Request(), us.Context.Response())
}

func (us *USession) AddValue(key, value string) *USession {
	us.Values[key] = value
	return us
}

func (us *USession) GetValue(key string) string {
	return convert.ToString(us.Values[key])
}
