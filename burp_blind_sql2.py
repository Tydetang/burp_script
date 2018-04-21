#-*- coding:utf8 -*-

from burp import IBurpExtender
from burp import IContextMenuFactory

from javax.swing import JMenuItem
from java.util import List, ArrayList
from java.net import URL

import re
import urllib2
from datetime import datetime

header = {
    'User-Agent':'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_3) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/64.0.3282.186 Safari/537.36'
}

class BurpExtender(IBurpExtender, IContextMenuFactory):
    def registerExtenderCallbacks(self,callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self.context = None

        callbacks.setExtensionName("Check_sql")
        callbacks.registerContextMenuFactory(self)

        return

    # 添加菜单
    def createMenuItems(self, context_menu):
        self.context = context_menu
        menu_list = ArrayList()
        # 添加到右键菜单
        menu_list.add(JMenuItem("Check_sql", actionPerformed=self.check_sql_menu))

        return menu_list

    def check_sql_menu(self, event):
        http_traffic = self.context.getSelectedMessages()

        for traffic in http_traffic:
            http_service = traffic.getHttpService()
            host = http_service.getHost()
            port = http_service.getPort()
            url = (str(host)+':'+str(port)).split()
            http_response = traffic.getResponse()
            http_request = traffic.getRequest()
            http_request = "11"+http_request
            print http_request
            header = http_request.split('HTTP/1.1')
            reg = r'\n(Cookie:.*?)\n'
            try:
                cookie = re.findall(re.compile(reg),header[1]).split()
                print cookie
            except:
                cookie = ''
            if "GET" in http_request:
                parameter = header[0].split('GET ')[1]
                self.check_get(cookie,parameter,url)
            elif "POST" in http_request:
                path = header[0].split('GET ')[1]
                self.check_post(cookie,path)
        return

    def check_get(self,cookie,parameter,host):
        start_time = datetime.now()
        timeout = 5
        if "?" in parameter:
            parameter = parameter+"' and sleep ("+str(timeout)+") %23"
            url = 'http://'+host[0]+parameter
            url = url.replace(' ','%20')
            print url
            if cookie != '':
                res = urllib2.Request(url,cookies=cookie,headers=header)
                response = urllib2.urlopen(res)
            else :
                res = urllib2.Request(url,headers=header)
                response = urllib2.urlopen(res)
            end_time = datetime.now()
            if (end_time - start_time).seconds >= timeout:
                print "sql_inject!!!"
            else :
                timeee = (end_time-start_time).seconds
                print timeee
                print "no inject"
        else :
            print "no parameter"

    def check_post(self,cookie,path):
        pass

