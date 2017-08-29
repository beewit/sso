package handler

import (
	"github.com/beewit/beekit/utils"
	"github.com/beewit/beekit/utils/union/weibo"
	"github.com/beewit/sso/global"
	"github.com/labstack/echo"
	"github.com/beewit/beekit/utils/convert"
	"github.com/beewit/beekit/utils/enum"
	"fmt"
)

func WeiboCode(c echo.Context) error {
	code := c.FormValue("code")
	if code != "" {
		accessToken, err := weibo.NewWeibo().GetAccessToken(global.WeiboAppKey, global.WeiboAppSecret, global.WeiboRedirectUri, code)
		if err != nil {
			return utils.RedirectAndAlert(c, "新浪微博AccessToken获取失败", "/")
		}
		convert.ToString(accessToken)
		//数据库查询用户绑定信息 accessToken.Uid
		sql := `SELECT status FROM account_auths LEFT JOIN account ON account.id=account_auths.account_id WHERE openid=?`
		rows, _ := global.DB.Query(sql, accessToken.Uid)
		if len(rows) != 1 {
			return utils.RedirectAndAlert(c, "您的微博没有绑定工蜂小智帐号哦", "/")
		}
		userInfo := rows[0]
		status := fmt.Sprintf("%s", userInfo["status"])

		if status != enum.NORMAL {
			return utils.RedirectAndAlert(c, "该帐号已被冻结", "/")
		}
		//设置Cookie    userInfo["mobile"]
		//GetToken(userInfo,)
		c.Cookie("backUrl")
		backUrl, err := c.Cookie("backUrl")
		if err != nil {
			return err
		}
		return utils.Redirect(c, backUrl.Value)
	}
	return utils.RedirectAndAlert(c, "新浪微博Code获取失败", "/")
}
