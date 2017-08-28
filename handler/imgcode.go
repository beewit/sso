package handler

import (
	"strconv"
	"github.com/labstack/echo"
	"github.com/beewit/sso/global"
	"github.com/beewit/beekit/utils"
	"net/http"
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
	c.Set("Content-Type", "image/png")
	c.Response().WriteHeader(http.StatusOK)
	utils.NewImage(d, 100, 40).WriteTo(c.Response().Writer)
	c.Response().Flush()
	global.RD.SetAndExpire(global.IMG_CODE, code, 60)
	return nil
}
