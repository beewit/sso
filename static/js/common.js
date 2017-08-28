/*
 *   url帮助类
 *    Request：获取url参数
 *   调用方式：LinkUrl.Request(参数名称)   返回：参数值
 *    ChangeUrlParas：改变url参数值，例如：index.html?k=2*
 *    调用方式：LinkUrl.ChangeUrlParas(当前url，参数名称，参数值)   返回：修改后的url
 *   var href=  LinkUrl.ChangeUrlParas('http://localhost:8080/home/main.html?id=10',id,12);
 *   href=  LinkUrl.ChangeUrlParas(href,name,'张三');
 *   结果：http://localhost:8080/home/main.html?id=12&name=张三
 * */
var LinkUrl = {
    Request: function (name) {
        var reg = new RegExp("(^|&)" + name + "=([^&]*)(&|$)", "i");
        var search = window.location.search.substr(1);
        search = decodeURI(search);
        var r = search.match(reg);
        if (r != null) {
            return (r[2]);
        }
        return "";
    },
    ChangeUrlParas: function (url, ref, value) {
        var str = "";
        url = this.DeleteParas(url, "page");
        if (url.indexOf('?') != -1)
            str = url.substr(url.indexOf('?') + 1);
        else
            return url + "?" + ref + "=" + value;
        var returnurl = "";
        var setparam = "";
        var arr;
        var modify = "0";
        if (str.indexOf('&') != -1) {
            arr = str.split('&');
            for (var i = 0; i < arr.length; i++) {
                if (arr[i].split('=')[0] == ref) {
                    setparam = value;
                    modify = "1";
                }
                else {
                    setparam = arr[i].split('=')[1];
                }
                returnurl = returnurl + arr[i].split('=')[0] + "=" + setparam + "&";
            }
            returnurl = returnurl.substr(0, returnurl.length - 1);
            if (modify == "0")
                if (returnurl == str)
                    returnurl = returnurl + "&" + ref + "=" + value;
        }
        else {
            if (str.indexOf('=') != -1) {
                arr = str.split('=');
                if (arr[0] == ref) {
                    setparam = value;
                    modify = "1";
                }
                else {
                    setparam = arr[1];
                }
                returnurl = arr[0] + "=" + setparam;
                if (modify == "0")
                    if (returnurl == str)
                        returnurl = returnurl + "&" + ref + "=" + value;
            }
            else
                returnurl = ref + "=" + value;
        }
        return url.substr(0, url.indexOf('?')) + "?" + returnurl;
    },
    DeleteParas: function (url, ref) {
        var str = "";
        if (url.indexOf('?') != -1) {
            str = url.substr(url.indexOf('?') + 1);
        }
        else {
            return url;
        }
        var arr = "";
        var returnurl = "";
        if (str.indexOf('&') != -1) {
            arr = str.split('&');
            for (var i = 0; i < arr.length; i++) {
                '';
                if (arr[i].split('=')[0] != ref) {
                    returnurl = returnurl + arr[i].split('=')[0] + "=" + arr[i].split('=')[1] + "&";
                }
            }
            return url.substr(0, url.indexOf('?')) + "?" + returnurl.substr(0, returnurl.length - 1);
        }
        else {
            arr = str.split('=');
            if (arr[0] == ref) {
                return url.substr(0, url.indexOf('?'));
            }
            else {
                return url;
            }
        }
    }
};
