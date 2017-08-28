package global

import (
	"github.com/beewit/beekit/conf"
	"github.com/beewit/beekit/log"
	"github.com/beewit/beekit/mysql"
	"github.com/beewit/beekit/redis"
	"fmt"
)

var (
	CFG  = conf.New("config.json")
	Log  = log.Logger
	DB   = mysql.DB
	RD   = redis.Cache
	IP   = CFG.Get("server.ip")
	Port = CFG.Get("server.port")
	Host = fmt.Sprintf("http://%s:%s", IP, Port)

	SmsGatewayUrl      = fmt.Sprintf("%s", CFG.Get("sms.gatewayUrl"))
	SmsAccessKeyId     = fmt.Sprintf("%s", CFG.Get("sms.accessKeyId"))
	SmsAccessKeySecret = fmt.Sprintf("%s", CFG.Get("sms.accessKeySecret"))
	SmsSignName        = fmt.Sprintf("%s", CFG.Get("sms.signName"))
	WeiboAppKey        = fmt.Sprintf("%s", CFG.Get("weibo.appKey"))
	WeiboAppSecret     = fmt.Sprintf("%s", CFG.Get("weibo.appSecret"))
	WeiboRedirectUri   = fmt.Sprintf("%s", CFG.Get("weibo.redirectUri"))
)

const (
	SMS_TEMPLATE_REG         = "SMS_83430283"
	SMS_TEMPLATE_PARAM       = "{\"code\":\"%s\"}"
	IMG_CODE                 = "imgCodeRedis"
	IMG_CODE_EXPIRE    int64 = 60
	SMS_CODE_EXPIRE    int64 = 10 * 60
)
