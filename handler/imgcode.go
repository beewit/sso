package handler

import (
	"strconv"
	"fmt"
	"github.com/labstack/echo"
	"github.com/beewit/sso/global"
	"github.com/beewit/beekit/utils"
	"github.com/beewit/beekit/utils/convert"
	"net/http"
)

func ImgCode(c echo.Context) error {
	d := make([]byte, 4)
	s := utils.NewLen(4)
	ss := ""
	d = []byte(s)
	for v := range d {
		d[v] %= 10
		ss += strconv.FormatInt(int64(d[v]), 32)
	}
	c.Set("Content-Type", "image/png")
	c.Response().WriteHeader(http.StatusOK)
	utils.NewImage(d, 100, 40).WriteTo(c.Response().Writer)
	fmt.Println(ss)
	c.Response().Flush()
	code, _ := convert.ToString(d)
	global.RD.SetAndExpire(global.ImgCode, code, 60)
	return nil
}
