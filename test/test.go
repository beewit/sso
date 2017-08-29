package main

import (
	"github.com/beewit/sso/global"
	"fmt"
	"encoding/json"
)

func main() {
	sql := `SELECT * FROM account_auths`
	rows, _ := global.DB.Query(sql)
	if len(rows) <= 0 {
		println("您的微博没有绑定工蜂小智帐号哦", "/")
	}
	mss := make([]map[string]string, 0, 0)
	for i, mi := range rows {
		ss := make(map[string]string)
		for k, v := range mi {
			ss[k] = fmt.Sprintf("%s", v)
		}
		mss = append(mss, ss)
		println(i)
	}
	js, _ := json.Marshal(mss)
	println(string(js[:]))
	v:=rows[0]
	println( fmt.Sprintf("%v",v["nickname"]))
}
