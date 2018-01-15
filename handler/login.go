package handler

import (
	"github.com/beewit/beekit/utils"
	"github.com/beewit/beekit/utils/encrypt"
	"github.com/beewit/sso/global"
	"github.com/beewit/wechat/mini"

	"encoding/json"
	"fmt"
	"github.com/beewit/beekit/log"
	"github.com/beewit/beekit/utils/convert"
	"github.com/beewit/beekit/utils/enum"
	"github.com/dgrijalva/jwt-go"
	"github.com/labstack/echo"
	"math/rand"
	"strings"
	"time"
)

func Login(c echo.Context) error {
	// upload param
	mobile := c.FormValue("mobile")
	password := c.FormValue("password")
	// auth
	sql := `SELECT id, password, mobile, nickname,salt FROM account WHERE mobile = ? AND status = ?`
	rows, _ := global.DB.Query(sql, mobile, enum.NORMAL)
	if len(rows) != 1 {
		return utils.Error(c, "帐号或密码不存在", nil)
	}
	userInfo := rows[0]
	pwd := convert.ToString(userInfo["password"])
	salt := convert.ToString(userInfo["salt"])
	if encrypt.Sha1Encode(password+salt) != pwd {
		return utils.Error(c, "密码错误", nil)
	}

	token, err := GetToken(userInfo)
	if err != nil {
		global.Log.Error(err.Error())
		return utils.Error(c, "服务器异常", nil)
	}

	//记录登录日志
	go func() {
		global.DB.InsertMap("account_action_logs", utils.ActionLogs(c, enum.ACTION_LOGIN, convert.MustInt64(userInfo["id"])))
	}()

	return utils.Success(c, "操作成功", map[string]string{
		"token": token,
	})
}

func Forget(c echo.Context) error {
	mobile := c.FormValue("mobile")
	smsCode := c.FormValue("sms_code")
	password := c.FormValue("password")
	if mobile == "" {
		return utils.Error(c, "待发送短信的手机号码不能为空", nil)
	}
	if smsCode == "" {
		return utils.Error(c, "短信验证码不能为空", nil)
	}
	if password == "" {
		return utils.Error(c, "新密码不能为空", nil)
	}
	if len(password) > 16 {
		return utils.Error(c, "新密码最长不能超过20位", nil)
	}
	if !utils.CheckRegexp(password, "^[0-9a-z]{6,16}$") {
		return utils.Error(c, "新密码仅包含字母数字字符", nil)
	}
	if !utils.CheckMobile(mobile) {
		return utils.Error(c, "手机号码格式错误", nil)
	}
	if !CheckMobile(mobile) {
		return utils.Error(c, "手机号码不存在", nil)
	}
	rdSmsCode, _ := global.RD.GetString(mobile + "_sms_code")
	if strings.ToLower(rdSmsCode) != strings.ToLower(smsCode) {
		return utils.Error(c, "短信验证码错误", nil)
	}
	userInfo := GetAccountByMobile(mobile)
	if userInfo == nil {
		return utils.Error(c, "该手机用户不存在", nil)
	}
	sql := "UPDATE account SET password=?,salt=? WHERE mobile=?"
	_, err := global.DB.Update(sql, encrypt.Sha1Encode(password+smsCode), smsCode, mobile)
	if err != nil {
		return utils.Error(c, "修改密码失败，"+err.Error(), nil)
	}
	global.RD.DelKey(mobile + "_sms_code")

	//记录登录日志
	go func() {
		global.DB.InsertMap("account_action_logs", utils.ActionLogs(c, enum.ACTION_FORGET, convert.MustInt64(userInfo["id"])))
	}()

	return utils.Success(c, "修改密码成功", nil)
}

func Register(c echo.Context) error {
	mobile := c.FormValue("mobile")
	smsCode := c.FormValue("sms_code")
	password := c.FormValue("password")
	shareMobile := c.FormValue("shareMobile")
	var shareAccountId int64
	var shareAccMap map[string]interface{}

	if mobile == "" {
		return utils.Error(c, "待发送短信的手机号码不能为空", nil)
	}
	if smsCode == "" {
		return utils.Error(c, "短信验证码不能为空", nil)
	}
	if password == "" {
		return utils.Error(c, "登陆密码不能为空", nil)
	}
	if len(password) > 16 {
		return utils.Error(c, "登陆密码最长不能超过16位", nil)
	}
	if !utils.CheckRegexp(password, "^[0-9a-z]{6,16}$") {
		return utils.Error(c, "登陆密码仅包含字母数字字符", nil)
	}
	if !utils.CheckMobile(mobile) {
		return utils.Error(c, "手机号码格式错误", nil)
	}
	if CheckMobile(mobile) {
		return utils.Error(c, "手机号码已注册", nil)
	}
	if shareMobile != "" {
		shareAccMap = GetAccountByMobile(shareMobile)
		if shareAccMap == nil {
			return utils.Error(c, "邀请者手机号码未注册账号", nil)
		}
	}
	rdSmsCode, setStrErr := global.RD.GetString(mobile + "_sms_code")
	if setStrErr != nil {
		global.Log.Error("注册帐号验证码Redis存储错误：" + setStrErr.Error())
	}
	if strings.ToLower(rdSmsCode) != strings.ToLower(smsCode) {
		return utils.Error(c, "短信验证码错误", nil)
	}
	id := utils.ID()
	//判断ip是否存在邀请关系
	shareIPAccMap := getShareAccount(c)
	if shareIPAccMap == nil {
		//如果没有邀请关系，判断填写邀请者手机号是否是有效账号
		if shareAccMap != nil {
			shareAccountId = convert.MustInt64(shareAccMap["id"])
		}
	} else {
		shareAccountId = convert.MustInt64(shareIPAccMap["account_id"])
	}
	//添加邀请者id
	sql := "INSERT INTO account (id,mobile,password,salt,status,ct_time,ct_ip,share_account_id) VALUES (?,?,?,?,?,?,?,?)"
	_, err := global.DB.Insert(sql, id, mobile, encrypt.Sha1Encode(password+smsCode), smsCode, enum.NORMAL,
		time.Now().Format("2006-01-02 15:04:05"), c.RealIP(), shareAccountId)
	if err != nil {
		return utils.Error(c, "注册失败，"+err.Error(), nil)
	}

	global.RD.DelKey(mobile + "_sms_code")

	//记录登录日志
	go func() {
		global.DB.InsertMap("account_action_logs", utils.ActionLogs(c, enum.ACTION_REGISTER, id))
	}()

	return utils.Success(c, "注册成功", nil)
}

func GetRand() string {
	rnd := rand.New(rand.NewSource(time.Now().UnixNano()))
	return fmt.Sprintf("%04v", rnd.Int31n(10000))
}

func RegSendSms(c echo.Context) error {
	mobile := c.FormValue("mobile")
	code := c.FormValue("code")
	t := c.FormValue("type")
	if mobile == "" {
		return utils.Error(c, "待发送短信的手机号码不能为空", nil)
	}
	if code == "" {
		return utils.Error(c, "待发送短信需要的图形验证码不能为空", nil)
	}

	if !utils.CheckMobile(mobile) {
		return utils.Error(c, "手机号码格式错误", nil)
	}
	//图形码校验
	imgCode := global.Session(c).GetValue(global.IMG_CODE) // global.RD.GetString(global.IMG_CODE)
	if imgCode != code {
		return utils.Error(c, "图形验证码错误", nil)
	}
	//短信接口数量限制或预警
	if t == "reg" {
		//注册帐号限制
		if CheckMobile(mobile) {
			return utils.Error(c, "手机号码已注册", nil)
		}
	}
	smsCode := GetRand()
	templateParam := fmt.Sprintf(global.SMS_TEMPLATE_PARAM, smsCode)
	smsClient := utils.NewSmsClient(global.SmsGatewayUrl)
	result, err := smsClient.Execute(
		global.SmsAccessKeyId,
		global.SmsAccessKeySecret,
		mobile,
		global.SmsSignName,
		global.SMS_TEMPLATE_REG,
		templateParam)
	if err != nil {
		fmt.Println("error:", err.Error())
		return utils.Error(c, "发送失败"+err.Error(), nil)
	} else {
		resultCode := fmt.Sprintf("%v", result["Code"])
		if resultCode == "OK" {
			_, setStrErr := global.RD.SetAndExpire(mobile+"_sms_code", smsCode, global.SMS_CODE_EXPIRE)
			if setStrErr != nil {
				global.Log.Error("注册帐号验证码Redis存储错误：" + setStrErr.Error())
				return utils.Error(c, "短信发送失败", nil)
			}
			return utils.Success(c, "短信发送成功", nil)
		} else {
			return utils.Error(c, "短信发送失败", nil)
		}
	}

}

func GetToken(account map[string]interface{}) (string, error) {
	accountMap := make(map[string]interface{})
	accountMap["id"] = account["id"]
	accountMap["random"] = utils.ID()
	accStr, _ := json.Marshal(accountMap)

	token := jwt.New(jwt.SigningMethodHS256)
	tk, err := token.SignedString(accStr)
	if err != nil {
		return "", err
	}
	alt := "account_login_token" + convert.ToString(account["id"])
	//清除该帐号下的其他Token
	oldToken, err2 := global.RD.GetString(alt)
	if err2 == nil {
		global.RD.DelKey(oldToken)
	}
	//Redis 7天
	global.RD.SetAndExpire(tk, accStr, 7*12*60*60)
	global.RD.SetAndExpire(alt, tk, 7*12*60*60)
	return tk, nil

}

func CheckRegMobile(c echo.Context) error {
	mobile := c.FormValue("mobile")
	if mobile == "" || !utils.CheckMobile(mobile) {
		return utils.Success(c, "", nil)
	}
	if CheckMobile(mobile) {
		return utils.Error(c, "手机号码已注册", nil)
	}
	return utils.Success(c, "", nil)
}

func CheckMobile(mobile string) bool {
	if mobile == "" {
		return false
	}
	sql := `SELECT mobile FROM account WHERE mobile = ? `
	rows, err := global.DB.Query(sql, mobile)
	if err != nil {
		return false
	}
	if len(rows) >= 1 {
		return true
	}
	return false
}

func GetAccountByMobile(mobile string) map[string]interface{} {
	if mobile == "" {
		return nil
	}
	sql := `SELECT * FROM account WHERE mobile = ? LIMIT 1 `
	rows, err := global.DB.Query(sql, mobile)
	if err != nil {
		return nil
	}
	if len(rows) != 1 {
		return nil
	}
	return rows[0]
}

func CheckLoginToken(c echo.Context) error {
	token := c.FormValue("token")
	m, err := CheckToken(token)
	if err != nil {
		log.Logger.Error(err.Error())
		return utils.AuthFail(c, "登录已失效")
	}
	if m == nil {
		return utils.AuthFail(c, "登录已失效")
	}
	return utils.Success(c, "登录成功", m)
}

func CheckToken(token string) (map[string]interface{}, error) {
	if token == "" {
		return nil, nil
	}
	tv, err := global.RD.GetString(token)
	if err != nil {
		global.Log.Error(err.Error())
		return nil, err
	}
	if tv == "" {
		return nil, nil
	}
	var m map[string]interface{}
	err = json.Unmarshal([]byte(tv), &m)
	if err != nil {
		global.Log.Error(err.Error())
		return nil, err
	}
	id := convert.ToString(m["id"])
	sql := "SELECT * FROM v_account WHERE id=? AND status = ? LIMIT 1"
	rows, _ := global.DB.Query(sql, id, enum.NORMAL)
	if len(rows) != 1 {
		global.Log.Warning("ID:%v，登陆帐号异常", id)
		return nil, nil
	}
	//更新登录token时间
	alt := "account_login_token" + id
	global.RD.SetAndExpire(token, tv, 7*12*60*60)
	global.RD.SetAndExpire(alt, token, 7*12*60*60)

	return rows[0], nil
}

func DeleteToken(c echo.Context) error {
	token := c.FormValue("token")
	if token == "" {
		return utils.ErrorNull(c, "token错误")
	}
	global.RD.DelKey(token)
	return utils.SuccessNullMsg(c, "退出成功")
}

func GetShareAccount(c echo.Context) error {
	return utils.SuccessNullMsg(c, getShareAccount(c) != nil)
}

func getShareAccount(c echo.Context) map[string]interface{} {
	sql := "SELECT * FROM download_access_log WHERE ip=? ORDER BY ct_time DESC LIMIT 1"
	rows, _ := global.DB.Query(sql, c.RealIP())
	if len(rows) > 0 {
		return rows[0]
	}
	return nil
}

func WechatMiniUnionIDLogin(c echo.Context) error {
	code := c.FormValue("code")
	if code == "" {
		return utils.ErrorNull(c, "获取用户凭证失败！")
	}
	ws, err := global.MiniWx.GetWxSessionKey(code)
	if err != nil {
		return utils.ErrorNull(c, "获取用户登录信息失败！")
	}
	if ws.ErrCode != 0 {
		return utils.ErrorNull(c, ws.ErrMsg)
	}
	wsStr := convert.ToObjStr(ws)
	global.Log.Info(wsStr)
	//存储redis记录
	mini_app_session_id := "mini_app_session_" + code
	_, err = global.RD.SetAndExpire(mini_app_session_id, wsStr, global.MINI_APP_SESSION_EXPIRE)
	if err != nil {
		return utils.ErrorNull(c, "获取用户信息失败")
	}
	auth, _ := GetAccountAuth(ws.Unionid, enum.WECHAT)
	if auth != nil {
		token, err := GetAccountAuthTokenByType(c, ws.Unionid, enum.WECHAT)
		if err != nil {
			return utils.ErrorNull(c, err.Error())
		}
		userinfo, err := CheckToken(token)
		if err != nil {
			return utils.ErrorNull(c, "获取用户信息失败")
		} else {
			return utils.Success(c, "登录成功", map[string]interface{}{
				"token":               token,
				"userinfo":            userinfo,
				"mini_app_session_id": mini_app_session_id,
			})
		}
	}
	return utils.Success(c, "获取mini_app_session_id成功", map[string]string{
		"mini_app_session_id": mini_app_session_id,
	})
}

//【小程序】绑定或注册账号并登录
func BindOrRegisterWechatMiniApi(c echo.Context) error {
	mobile := c.FormValue("mobile")
	password := c.FormValue("pwd")
	smsCode := c.FormValue("smsCode")
	userinfo := c.FormValue("userinfo")
	miniAppSessionId := c.FormValue("miniAppSessionId")
	if !utils.CheckMobile(mobile) {
		return utils.ErrorNull(c, "手机号码格式错误")
	}
	if smsCode == "" {
		return utils.ErrorNull(c, "短信验证码不能为空")
	}
	rdSmsCode, setStrErr := global.RD.GetString(mobile + "_sms_code")
	if setStrErr != nil {
		global.Log.Error("注册帐号验证码Redis存储错误：" + setStrErr.Error())
	}
	if strings.ToLower(rdSmsCode) != strings.ToLower(smsCode) {
		return utils.ErrorNull(c, "短信验证码错误")
	}
	wsStr, err := global.RD.GetString(miniAppSessionId)
	if err != nil {
		return utils.ErrorNull(c, "获取用户登录标识失败")
	}
	var ws *mini.WxSesstion
	err = json.Unmarshal([]byte(wsStr), &ws)
	if err != nil {
		return utils.ErrorNull(c, "获取用户登录标识失败")
	}
	var user *mini.WxUserInfo
	if userinfo != "" {
		json.Unmarshal([]byte(userinfo), &user)
	}
	acc := GetAccountByMobile("mobile")
	auth, _ := GetAccountAuth(ws.Unionid, enum.WECHAT)
	if auth != nil && auth["account_id"] != acc["id"] {
		return utils.ErrorNull(c, "已绑定过其他账号，请取消绑定后进行绑定")
	}
	if acc == nil {
		//注册流程
		if password == "" {
			return utils.ErrorNull(c, "登陆密码不能为空")
		}
		if len(password) > 16 {
			return utils.ErrorNull(c, "登陆密码最长不能超过16位")
		}
		if !utils.CheckRegexp(password, "^[0-9a-z]{6,16}$") {
			return utils.ErrorNull(c, "登陆密码仅包含字母数字字符")
		}
		id := utils.ID()
		sql := "INSERT INTO account (id,mobile,password,salt,status,ct_time,ct_ip) VALUES (?,?,?,?,?,?,?,?)"
		_, err := global.DB.Insert(sql, id, mobile, encrypt.Sha1Encode(password+smsCode), smsCode, enum.NORMAL,
			time.Now().Format("2006-01-02 15:04:05"), c.RealIP())
		if err != nil {
			return utils.Error(c, "注册失败，"+err.Error(), nil)
		}
		//记录注册日志
		go func() {
			global.DB.InsertMap("account_action_logs", utils.ActionLogs(c, enum.ACTION_REGISTER, id))
		}()

		auth["account_id"] = id
		auth["ct_time"] = utils.CurrentTime()

	} else {
		//绑定流程
		if convert.ToString(acc["status"]) != enum.NORMAL {
			return utils.ErrorNull(c, "账号已被冻结无法绑定")
		}
	}
	auth["ip"] = c.RealIP()
	auth["mini_openid"] = ws.Openid
	auth["unionID"] = ws.Unionid
	auth["ut_time"] = utils.CurrentTime()
	if user != nil {
		auth["nickname"] = user.NickName
		auth["photo"] = user.AvatarUrl
		auth["type"] = enum.WECHAT
	}
	global.RD.DelKey(mobile + "_sms_code")
	_, err = global.DB.InsertMap("account_auths", auth)
	if err != nil {
		return utils.ErrorNull(c, "绑定账号失败")
	}
	return utils.SuccessNull(c, "绑定成功")
}

func CheckMiniAppSessionId(c echo.Context) error {
	miniAppSessionId := c.FormValue("miniAppSessionId")
	wsStr, err := global.RD.GetString(miniAppSessionId)
	if err != nil {
		return utils.ErrorNull(c, "获取用户登录标识失败")
	}
	if wsStr == "" {
		return utils.ErrorNull(c, "获取用户登录标识失败")
	}
	return utils.SuccessNull(c, "获取用户登录标识成功")
}
