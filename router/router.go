package router

import (
	"github.com/beewit/beekit/utils"
	"github.com/beewit/beekit/utils/convert"
	"github.com/beewit/sso/global"
	"github.com/beewit/sso/handler"

	"github.com/labstack/echo"

	"fmt"

	"github.com/labstack/echo/middleware"
)

func Start() {
	fmt.Printf("登陆授权系统启动")

	e := echo.New()

	e.Use(middleware.RequestID())

	e.Static("/static", "static")
	e.Static("/page", "page")
	e.File("/", "page/login.html")

	e.POST("/pass/login", handler.Login)
	e.POST("/pass/register", handler.Register)
	e.POST("/pass/regSendSms", handler.RegSendSms)
	e.POST("/pass/checkRegMobile", handler.CheckRegMobile)
	e.POST("/pass/checkToken", handler.CheckLoginToken)

	e.GET("/union/weibo/code", handler.WeiboCode)

	e.GET("/img/code", handler.ImgCode)

	utils.Open(global.Host)
	port := ":" + convert.ToString(global.Port)
	e.Logger.Fatal(e.Start(port))
}
