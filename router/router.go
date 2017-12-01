package router

import (
	"github.com/beewit/beekit/utils"
	"github.com/beewit/beekit/utils/convert"
	"github.com/beewit/sso/global"
	"github.com/beewit/sso/handler"

	"github.com/labstack/echo"

	"fmt"

	"github.com/gorilla/sessions"
	"github.com/labstack/echo-contrib/session"
)

func Start() {
	fmt.Printf("登陆授权系统启动")

	e := echo.New()
	e.Use(session.Middleware(sessions.NewCookieStore([]byte("secret"))))

	e.Static("/static", "static")
	e.Static("/page", "page")
	e.File("/", "page/login.html")

	e.POST("/pass/deleteToken", handler.DeleteToken)
	e.POST("/pass/login", handler.Login)
	e.POST("/pass/register", handler.Register)
	e.POST("/pass/forget", handler.Forget)
	e.POST("/pass/regSendSms", handler.RegSendSms)
	e.POST("/pass/checkRegMobile", handler.CheckRegMobile)
	e.POST("/pass/checkToken", handler.CheckLoginToken)

	e.GET("/union/weibo/code", handler.WeiboCode)
	e.GET("/union/wechat/code", handler.WechatCode)
	e.POST("/union/login", handler.GetUnionLoginApi)
	e.POST("/union/bind", handler.UnionBindApi, handler.Filter)
	e.GET("/img/code", handler.ImgCode)

	utils.Open(global.Host)
	port := ":" + convert.ToString(global.Port)
	e.Logger.Fatal(e.Start(port))
}
