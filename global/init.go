package global

import (
	"github.com/beewit/beekit/conf"
	"github.com/beewit/beekit/log"
	"github.com/beewit/beekit/mysql"
	"github.com/beewit/beekit/redis"
	"fmt"
	"github.com/beewit/beekit/utils/convert"
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
)

const (
	SMS_TEMPLATE_REG         = "SMS_83430283"
	SMS_TEMPLATE_PARAM       = "{\"code\":\"%v\"}"
	IMG_CODE                 = "imgCodeRedis"
	IMG_CODE_EXPIRE    int64 = 60
	SMS_CODE_EXPIRE    int64 = 10 * 60
)
