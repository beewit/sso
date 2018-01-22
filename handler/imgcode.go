package handler

import (
	"github.com/beewit/beekit/utils"
	"github.com/beewit/sso/global"
	"github.com/labstack/echo"
	"net/http"
	"strconv"
)

func ImgCode(c echo.Context) error {
	d := make([]byte, 4)
	s := utils.NewLen(4)
	code := ""
	d = []byte(s)
	for v := range d {
		d[v] %= 10
		code += strconv.FormatInt(int64(d[v]), 32)
	}
	miniAppSessionId := c.FormValue("miniAppSessionId")

	global.RD.SetAndExpire(miniAppSessionId+"_img_code", code, global.IMG_CODE_EXPIRE)

	global.Session(c).AddValue(global.IMG_CODE, code).Saves()
	c.Set("Content-Type", "image/png")
	c.Response().WriteHeader(http.StatusOK)
	utils.NewImage(d, 100, 40).WriteTo(c.Response().Writer)
	c.Response().Flush()

	//global.RD.SetAndExpire(global.IMG_CODE, code, 60)
	return nil
}
