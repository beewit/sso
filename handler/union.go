package handler

import (
	//	"fmt"

	"fmt"
	"github.com/beewit/beekit/utils"
	"github.com/beewit/beekit/utils/convert"
	"github.com/beewit/beekit/utils/enum"
	"github.com/beewit/beekit/utils/union/wechat"
	"github.com/beewit/beekit/utils/union/weibo"
	"github.com/beewit/sso/global"
	"github.com/labstack/echo"
	"github.com/pkg/errors"
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
		return commonLogin(accessToken.Uid, enum.WEIBO, c)
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
		unionID := convert.ToString(atMap["unionid"])
		if unionID == "" {
			return utils.RedirectAndAlert(c, "微信AccessToken获取失败", "/")
		}
		return commonLogin(unionID, enum.WECHAT, c)
	}
	return utils.RedirectAndAlert(c, "微信Code获取失败", "/")
}

func commonLogin(unionID, t string, c echo.Context) error {
	token, err := GetAccountAuthTokenByType(c, unionID, t)
	if err != nil {
		return utils.RedirectAndAlert(c, err.Error(), "/")
	}
	c.Cookie("backUrl")
	backUrl, err := c.Cookie("backUrl")
	if err != nil {
		return utils.RedirectAndAlert(c, "登陆成功可无回调地址", "/")
	}
	goBackUrl := backUrl.Value
	if strings.Contains(backUrl.Value, "?") {
		goBackUrl = goBackUrl + "&token=" + token
	} else {
		goBackUrl = goBackUrl + "?token=" + token
	}
	return utils.Redirect(c, goBackUrl)
}

func UnionBindApi(c echo.Context) error {
	itf := c.Get("account")
	if itf == nil {
		return utils.AuthFailNull(c)
	}
	acc := global.ToInterfaceAccount(itf)
	if acc == nil {
		return utils.AuthFailNull(c)
	}
	m := map[string]interface{}{}
	m["account_id"] = acc.ID
	gender := "gender"
	t := c.FormValue("t")
	if t == enum.WEIBO {
		uid := c.FormValue("uid")
		accessToken := c.FormValue("accessToken")
		wb, err := getWeibo(uid, accessToken)
		if err != nil {
			return utils.ErrorNull(c, err.Error())
		}
		m["nickname"] = wb.Name
		m["photo"] = wb.AvatarHD
		m["type"] = enum.WEIBO
		m["unionID"] = wb.ID
		if wb.Gender == "m" {
			gender = "男"
		} else if wb.Gender == "f" {
			gender = "女"
		}

	} else if t == enum.WECHAT {
		code := c.FormValue("code")
		wt, err := getWechat(code)
		if err != nil {
			return utils.ErrorNull(c, err.Error())
		}
		m["nickname"] = wt.NickName
		m["photo"] = wt.HeadImgURL
		m["type"] = enum.WECHAT
		m["unionID"] = wt.UnionID
		m["openid_pulic"] = wt.OpenID
		if wt.Sex == 1 {
			gender = "男"
		} else if wt.Sex == 2 {
			gender = "女"
		}
	} else if t == enum.WECHAT_MINI {
		//微信小程序绑定，并获取token

	} else {
		return utils.ErrorNull(c, fmt.Sprintf("无该类型【%s】第三方登录绑定接口", t))
	}
	err := saveAccountAuth(m)
	if err != nil {
		global.Log.Error(err.Error())
		return utils.ErrorNull(c, err.Error())
	}
	//如果没有头像，则更新头像
	//if acc.Photo == "" || acc.Nickname == "" {
	err = updateAccInfo(acc.ID, convert.ToString(m["nickname"]), convert.ToString(m["photo"]), gender)
	if err != nil {
		global.Log.Error("修改头像个人信息失败")
	} else {
		global.Log.Info("修改头像个人信息成功")
	}
	//}

	//记录登录日志
	go func() {
		global.DB.InsertMap("account_action_logs", utils.ActionLogsMap(c, enum.UNION_ACCOUNT_BIND, t, acc.ID))
	}()

	return utils.SuccessNull(c, "绑定成功")
}

func GetUnionLoginApi(c echo.Context) error {
	t := c.FormValue("t")
	if t == enum.WEIBO {
		return geWeiboLoginToken(c)
	} else if t == enum.WECHAT {
		return getWechatLoginToken(c)
	} else {
		return utils.ErrorNull(c, fmt.Sprintf("无该类型【%s】第三方登录接口", t))
	}
}

func geWeiboLoginToken(c echo.Context) error {
	uid := c.FormValue("uid")
	accessToken := c.FormValue("accessToken")
	wb, _ := getWeibo(uid, accessToken)
	token, err := GetAccountAuthTokenByType(c, uid, enum.WEIBO)
	if err != nil {
		return utils.Error(c, err.Error(), wb)
	}
	return utils.SuccessNullMsg(c, map[string]interface{}{
		"token": token,
		"info":  wb,
	})
}

func getWechatLoginToken(c echo.Context) error {
	code := c.FormValue("code")
	wt, err := getWechat(code)
	if err != nil {
		return utils.Error(c, err.Error(), wt)
	}
	token, err := GetAccountAuthTokenByType(c, wt.UnionID, enum.WECHAT)
	if err != nil {
		return utils.Error(c, err.Error(), wt)
	}
	return utils.SuccessNullMsg(c, map[string]interface{}{
		"token": token,
		"info":  wt,
	})
}

func GetAccountAuthTokenByType(c echo.Context, unionID, t string) (token string, err error) {
	userInfo, err := GetAccountAuth(unionID, t)
	if err != nil {
		return
	}
	status := convert.ToString(userInfo["status"])
	userInfo["id"] = userInfo["account_id"]
	if status != enum.NORMAL {
		err = errors.New("该帐号已被冻结")
		return
	}
	token, err = GetToken(userInfo)

	//记录登录日志
	go func() {
		global.DB.InsertMap("account_action_logs", utils.ActionLogsMap(c, enum.UNION_ACCOUNT_LOGIN, t, convert.MustInt64(userInfo["account_id"])))
	}()

	return
}

func GetAccountAuth(unionID, t string) (row map[string]interface{}, err error) {
	sql := `SELECT account_id,status,mobile FROM account_auths LEFT JOIN account ON account.id=account_auths.account_id WHERE unionID=? AND type=?`
	rows, _ := global.DB.Query(sql, unionID, t)
	if len(rows) != 1 {
		err = errors.New(fmt.Sprintf("您的%s没有绑定工蜂小智帐号哦", t))
		return
	}
	row = rows[0]
	return
}

func getWeibo(uid, accessToken string) (wb weibo.Weibo, err error) {
	if uid == "" || accessToken == "" {
		err = errors.New("微博需要的uid、AccessToken不能为空")
		return
	}
	wb, err = weibo.NewWeibo().User(accessToken, uid)
	return
}

func getWechat(code string) (wt wechat.Wechat, err error) {
	if code == "" {
		err = errors.New("微信Code获取失败")
		return
	}
	w := wechat.NewWechat()
	var atMap map[string]interface{}
	atMap, err = w.GetAccessToken(global.WechatAPPAppId, global.WechatAPPAppSecret, code)
	if err != nil {
		global.Log.Error("微信AccessToken获取失败，ERROR：%s", err.Error())
		err = errors.New("微信AccessToken获取失败")
		return
	}
	unionID := convert.ToString(atMap["unionid"])
	accessToken := convert.ToString(atMap["access_token"])
	if unionID == "" || accessToken == "" {
		global.Log.Error("unionID、access_token错误")
		err = errors.New("unionID、access_token错误")
		return
	}
	wt, err = w.User(accessToken, unionID)
	if err != nil {
		global.Log.Error("获取用户信息失败，ERROR：%s", err.Error())
		err = errors.New("获取用户信息失败")
		return
	}
	return
}

func saveAccountAuth(m map[string]interface{}) (err error) {
	m["ip"] = utils.GetIp()
	//t := convert.ToString(m["type"])
	//unionID := convert.ToString(m["unionID"])
	_, err = GetAccountAuth(convert.ToString(m["unionID"]), convert.ToString(m["type"]))
	if err != nil {
		//新增项
		m["id"] = utils.ID()
		m["ct_time"] = utils.CurrentTime()
		m["ut_time"] = m["ct_time"]
		_, err = global.DB.InsertMap("account_auths", m)
		if err != nil {
			err = errors.New("绑定账号失败")
		}
		return
	} else {
		//修改项
		//sql := "UPDATE account_auths SET nickname=?,photo=?,openid_pulic=?,openid=?,unionID=?,ut_time=? WHERE account_id=? AND type=? "
		//_, err = global.DB.Update(sql, m["nickname"], m["photo"], m["openid_pulic"], m["openid"], unionID, utils.CurrentTime(), m["account_id"], t)
		err = errors.New("已绑定过其他账号，请取消绑定后进行绑定")
	}
	return
}

func updateAccInfo(accId int64, nickname, photo, gender string) (err error) {
	sql := "UPDATE account SET nickname=?,photo=?,gender=? WHERE id=?"
	_, err = global.DB.Update(sql, nickname, photo, gender, accId)
	return
}

func CancelUnion(c echo.Context) error {
	acc, err := GetAccount(c)
	if err != nil {
		return err
	}
	t := c.FormValue("type")
	unionID := c.FormValue("unionID")
	sql := "DELETE FROM account_auths WHERE account_id=? AND type=? AND unionID=?"
	_, err = global.DB.Delete(sql, acc.ID, t, unionID)
	if err != nil {
		return utils.ErrorNull(c, "取消绑定失败")
	}
	return utils.SuccessNull(c, "取消绑定成功")
}
