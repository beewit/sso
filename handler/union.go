package handler

import (
	//	"fmt"

	"github.com/beewit/beekit/utils"
	"github.com/beewit/beekit/utils/convert"
	"github.com/beewit/beekit/utils/enum"
	"github.com/beewit/beekit/utils/union/weibo"
	"github.com/beewit/beekit/utils/union/wechat"
	"github.com/beewit/sso/global"
	"github.com/labstack/echo"
	"strings"
)

func WeiboCode(c echo.Context) error {
	code := c.FormValue("code")
	if code != "" {
		accessToken, err := weibo.NewWeibo().GetAccessToken(global.WeiboAppKey, global.WeiboAppSecret, global.WeiboRedirectUri, code)
		if err != nil {
			return utils.RedirectAndAlert(c, "新浪微博AccessToken获取失败", "/")
		}
		convert.ToString(accessToken)
		if accessToken.Uid == "" {
			return utils.RedirectAndAlert(c, "新浪微博AccessToken获取失败", "/")
		}
		return commonLogin(accessToken.Uid, "新浪微博", c)
	}
	return utils.RedirectAndAlert(c, "新浪微博Code获取失败", "/")

}

func WechatCode(c echo.Context) error {
	code := c.FormValue("code")
	if code != "" {
		w := wechat.NewWechat()
		atMap, err := w.GetAccessToken(global.WechatAppId, global.WechatAppSecret, code)
		if err != nil {
			global.Log.Error(err.Error())
			return utils.RedirectAndAlert(c, "微信AccessToken获取失败", "/")
		}
		openId := convert.ToString(atMap["openid"])
		if openId == "" {
			return utils.RedirectAndAlert(c, "微信AccessToken获取失败", "/")
		}
		return commonLogin(openId, "微信", c)
	}
	return utils.RedirectAndAlert(c, "微信Code获取失败", "/")
}

func commonLogin(openId, t string, c echo.Context) error {
	sql := `SELECT account_id,status,mobile FROM account_auths LEFT JOIN account ON account.id=account_auths.account_id WHERE
		openid=? AND type=?`
	rows, _ := global.DB.Query(sql, openId, t)
	if len(rows) != 1 {
		return utils.RedirectAndAlert(c, "您的"+t+"没有绑定工蜂小智帐号哦", "/")
	}
	userInfo := rows[0]

	status := convert.ToString(userInfo["status"])
	userInfo["id"] = userInfo["account_id"]
	if status != enum.NORMAL {
		return utils.RedirectAndAlert(c, "该帐号已被冻结", "/")
	}

	c.Cookie("backUrl")
	backUrl, err := c.Cookie("backUrl")
	if err != nil {
		return utils.RedirectAndAlert(c, "登陆成功可无回调地址", "/")
	}
	token, err := GetToken(userInfo)
	if err != nil {
		global.Log.Error(err.Error())
		return utils.Error(c, "服务器异常", nil)
	}
	goBackUrl := backUrl.Value
	if strings.Contains(backUrl.Value, "?") {
		goBackUrl = goBackUrl + "&token=" + token
	} else {
		goBackUrl = goBackUrl + "?token=" + token
	}
	return utils.Redirect(c, goBackUrl)
}
