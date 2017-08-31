package main

import (
	"github.com/beewit/sso/global"
	"github.com/beewit/beekit/utils/convert"
)

func main() {
	println("测试")
	sql := `SELECT * FROM account_auths LEFT JOIN account ON account.id=account_auths.account_id `
	rows, _ := global.DB.Query(sql )

	rows[0]["id"] = rows[0]["account_id"]
	println(convert.ToString(rows[0]["id"]))
}
