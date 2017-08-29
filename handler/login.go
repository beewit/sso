package handler

import (
	"github.com/beewit/beekit/utils"
	"github.com/beewit/beekit/utils/encrypt"
	"github.com/beewit/sso/global"

	"github.com/dgrijalva/jwt-go"
	"github.com/labstack/echo"
	"fmt"
	"encoding/json"
	"github.com/pkg/errors"
	"github.com/beewit/beekit/utils/convert"
)

func Login(c echo.Context) error {
	// upload param
	mobile := c.FormValue("mobile")
	password := c.FormValue("password")
	// auth
	sql := `SELECT id, password, mobile, nickname,salt FROM account WHERE mobile = ? AND status = 1`
	rows, _ := global.DB.Query(sql, mobile)
	if len(rows) != 1 {
		return utils.Error(c, "帐号或密码不存在", nil)
	}
	userInfo := rows[0]
	pwd := convert.ToString(userInfo["password"])
	salt := convert.ToString(userInfo["salt"])
	if encrypt.Sha1Encode(password+salt) != pwd {
		return utils.Error(c, "密码错误", nil)
	}

	token, err := GetToken(userInfo, mobile)
	if err != nil {
		global.Log.Error(err.Error())
		return utils.Error(c, "服务器异常", nil)
	}

	return utils.Success(c, "操作成功", map[string]string{
		"token": token,
	})
}

func GetToken(account map[string]interface{}, mobile string) (string, error) {
	iw, _ := utils.NewIdWorker(1)
	idw, idErr := iw.NextId()
	if idErr != nil {
		return "", errors.New("ID生成器发生错误")
	}
	accountMap := make(map[string]interface{})
	accountMap["id"] = account["id"]
	accountMap["random"] = idw
	accStr, _ := json.Marshal(accountMap)

	token := jwt.New(jwt.SigningMethodHS256)
	tk, err := token.SignedString(accStr)
	if err != nil {
		return "", err
	}

	//Redis 12小时
	global.RD.SetAndExpire(global.LoginToken(mobile), tk, 12*60*60)
	return tk, nil

}

func Register(c echo.Context) error {
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
		return utils.Error(c, "登陆密码不能为空", nil)
	}
	if len(password) > 20 {
		return utils.Error(c, "登陆密码最长不能超过20位", nil)
	}
	if utils.CheckRegexp(password, "/^[0-9A-Z_-]*$/i") {
		return utils.Error(c, "登陆密码仅包含字母数字字符，包括破折号、下划线", nil)
	}
	if !utils.CheckMobile(mobile) {
		return utils.Error(c, "手机号码格式错误", nil)
	}
	if CheckMobile(mobile) {
		return utils.Error(c, "手机号码已注册", nil)
	}
	rdSmsCode, setStrErr := global.RD.GetString(mobile + "_sms_code")
	if setStrErr != nil {
		global.Log.Error("注册帐号验证码Redis存储错误：" + setStrErr.Error())
	}
	if rdSmsCode != smsCode {
		return utils.Error(c, "短信验证码错误", nil)
	}

	sql := "INSERT INTO account (id,mobile,password,salt,status) VALUES (?,?,?,?,1)"
	iw, _ := utils.NewIdWorker(1)
	id, idErr := iw.NextId()
	if idErr != nil {
		return utils.Error(c, "ID生成器发生错误", nil)
	}
	_, err := global.DB.Insert(sql, id, mobile, encrypt.Sha1Encode(password+smsCode), smsCode)
	if err != nil {
		return utils.Error(c, "注册失败，"+err.Error(), nil)
	}

	global.RD.DelKey(mobile + "_sms_code")
	return utils.Success(c, "注册成功", nil)
}

func RegSendSms(c echo.Context) error {
	mobile := c.FormValue("mobile")
	code := c.FormValue("code")
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
	imgCode, _ := global.RD.GetString(global.IMG_CODE)
	if imgCode != code {
		return utils.Error(c, "图形验证码错误", nil)
	}
	//短信接口数量限制

	//注册帐号限制
	if CheckMobile(mobile) {
		return utils.Error(c, "手机号码已注册", nil)
	}

	smsCode := utils.NewLen(4)
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
			}
			return utils.Success(c, "短信发送成功", nil)
		} else {
			return utils.Error(c, "短信发送失败", nil)
		}
	}

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
