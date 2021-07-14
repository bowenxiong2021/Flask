#coding:utf-8
import sys
import datetime
from flask import Flask
from flask import request
import requests as requests_local
#from flask import jsonify
from flask import Flask,jsonify
from flask import Response
import os
import codecs
import chardet
from flask import abort
import httplib
import subprocess
import urllib,urllib2
import json as json_local
import requests as requests_local
import smtplib
import base64
import pymysql.cursors
from email.mime.multipart import MIMEMultipart  
from email.mime.text import MIMEText  
from email.mime.image import MIMEImage
from Crypto.Cipher import AES  
from binascii import b2a_hex, a2b_hex

app = Flask(__name__)
reload(sys)
sys.setdefaultencoding('utf-8')
@app.route('/get_ip', methods=['get','post'])
def ceshi():
	return request.remote_addr
def api_auth(id,key):
	user = id
	pwd = key
	date = "powershell New-Object System.DirectoryServices.DirectoryEntry 'LDAP://dc=lexinfintech,dc=com','%s','%s'" %(user,pwd)
	cmd = '"'+date+'"'
	
	jieguo = os.system(cmd)
	if jieguo == 0:
		date = "Get-ADGroupMember -Identity api|where {$_.SamAccountName -eq '%s'}|Get-ADUser" %(user)
		cmd = 'powershell '+'"'+date+'"'
		print cmd
		jieguo = os.popen(cmd).read()
		print jieguo
		if jieguo == "":
			return "4006"
		else:
			return "200"
	else:
		return "4007"

@app.route('/post_info', methods=['post'])
def post_info():
	data = request.json
	name = data ['name']
	computer = data ['computer']
	ip = data ['ip']
	text = data ['text']
	time = data ['time']
	path = data ['path']
	print text
	connection = pymysql.connect(host='10.1.49.187', port=3306, user='root', password='Liu@2016', db='postfile',charset='utf8mb4', cursorclass=pymysql.cursors.DictCursor)
	# 通过cursor创建游标
	cursor = connection.cursor()
	# 创建sql 语句，并执行
	sql = "INSERT INTO csv (`name`,`computer`,`ipv4`,`text`,'time','path') VALUES ('%s','%s','%s','%s')" % (name,computer,ip,text,time,path)
	cursor.execute(sql)
	# 提交SQL
	connection.commit()
	connection.close()
	return text
@app.route('/qiyeit_info', methods=['post'])
def qiyeit_info():
	data = request.json
	print data
	adsi = data ['adsi']
	disk_c_allsize = data ['disk_c_allsize']
	disk_c_freesize_rate = data ['disk_c_freesize_rate']
	hostname = data ['hostname']
	ip = data ['ip']
	name = data ['name']
	report_time = data ['report_time']
	sn = data ['sn']
	system_name = data ['system_name']
	connection = pymysql.connect(host='10.1.49.187', port=3306, user='root', password='Liu@2016', db='qiyeit',charset='utf8mb4', cursorclass=pymysql.cursors.DictCursor)
	# 通过cursor创建游标
	cursor = connection.cursor()
	# 创建sql 语句，并执行
	sql = "INSERT INTO body_all (`adsi`,`disk_c_allsize`,`disk_c_freesize_rate`,`hostname`,`ip`,`name`,`report_time`,`sn`,`system_name`) VALUES ('%s','%s','%s','%s','%s','%s','%s','%s','%s')" % (adsi,disk_c_allsize,disk_c_freesize_rate,hostname,ip,name,report_time,sn,system_name)
	cursor.execute(sql)
	# 提交SQL
	connection.commit()
	connection.close()
	return name
@app.route('/qiyeit_software_info', methods=['post'])
def qiyeit_software_info():
	data = request.json
	print data
	sn = data ['sn']
	DisplayName = data ['DisplayName']
	DisplayVersion = data ['DisplayVersion']
	InstallDate = data ['InstallDate']
	PSChildName = data ['PSChildName']
	connection = pymysql.connect(host='10.1.49.187', port=3306, user='root', password='Liu@2016', db='qiyeit',charset='utf8mb4', cursorclass=pymysql.cursors.DictCursor)
	# 通过cursor创建游标
	cursor = connection.cursor()
	# 创建sql 语句，并执行
	sql = "INSERT INTO software (`sn`,`DisplayName`,`DisplayVersion`,`InstallDate`,`PSChildName`) VALUES ('%s','%s','%s','%s','%s')" % (sn,DisplayName,DisplayVersion,InstallDate,PSChildName)
	cursor.execute(sql)
	# 提交SQL
	connection.commit()
	connection.close()
	return sn
@app.route('/qiyeit_wifi_info', methods=['post'])
def qiyeit_wifi_info():
	data = request.json
	print data
	Fdep_name = data ['Fdep_name']
	Fdep_id = data ['Fdep_id']
	Fenglish_name = data ['Fenglish_name']
	Fwifi_time = data ['Fwifi_time']
	connection = pymysql.connect(host='10.1.50.90', port=3306, user='root', password='w^8XDL^B^uw*7FB1', db='checking_in',charset='utf8mb4', cursorclass=pymysql.cursors.DictCursor)
	# 通过cursor创建游标
	cursor = connection.cursor()
	# 创建sql 语句，并执行
	sql = "INSERT INTO t_lexin_wifi_info (`Fdep_name`,`Fenglish_name`,`Fwifi_time`,`Fdep_id`) VALUES ('%s','%s','%s','%s')" % (Fdep_name,Fenglish_name,Fwifi_time,Fdep_id)
	cursor.execute(sql)
	# 提交SQL
	connection.commit()
	connection.close()
	return Fdep_name
@app.route('/get_auth', methods=['get'])
def get_auth():
	user = request.args.get('user')
	password = request.args.get('password')
	date = "powershell New-Object System.DirectoryServices.DirectoryEntry 'LDAP://dc=lexinfintech,dc=com','%s','%s'" %(user,password)
	cmd = '"'+date+'"'
	print cmd
	result = os.system(cmd)
	return str(result)
@app.route('/get_department', methods=['get','post'])
def get_department(): 
	user = request.args.get('user')
	if len(user) == 0:
		return "4001"
	date = "powershell (Get-ADUser %s -Properties *).CanonicalName" %(user)
	cmd = '"'+date+'"'
	print cmd
	result = os.popen(cmd).read()
	return result.decode('gbk').encode('utf-8')
@app.route('/json', methods=['get','post'])
def json(): 
	date = request.get_data()
	dict1 = json.loads(date)
	print date
	return json.dumps(dict1["data"]).decode('gbk')
@app.route('/auth', methods=['post'])
def auth(): 
	user = request.form.get('user')
	password = request.form.get('password')
	date = "powershell New-Object System.DirectoryServices.DirectoryEntry 'LDAP://dc=lexinfintech,dc=com','%s','%s'" %(user,password)
	cmd = '"'+date+'"'
	print cmd
	result = os.system(cmd)
	return jsonify(result)
@app.route('/get_user', methods=['get','post'])
def get_user(): 
	user = request.args.get('user')
	if len(user) == 0:
		return "4001"
	date = "powershell get-aduser %s" %(user)
	cmd = '"'+date+'"'
	print cmd
	result = os.popen(cmd).read()
	return result.decode('gbk').encode('utf-8')
@app.route('/get_group', methods=['get','post'])
def get_group(): 
	group = request.args.get('group')
	if len(group) == 0:
		return "4001"
	date = "powershell get-adgroup %s" %(group)
	cmd = '"'+date+'"'
	cmd = cmd.encode('gbk')
	print cmd
	result = os.popen(cmd).read()
	return result.decode('gbk').encode('utf-8')
@app.route('/set_user', methods=['post'])
def set_user(): 
	user = request.form.get('user')
	displayname = request.form.get('displayname')
	displayname = displayname.decode('gbk').encode('utf-8')
	date = "powershell set-aduser -identity %s -displayname %s" %(user,displayname)
	cmd = '"'+date+'"'
	print cmd
	a = sys.getdefaultencoding()
	print a
	result = os.system(cmd)
	return str(result)
@app.route('/set_city', methods=['post','get'])
def set_city():
	user = request.form.get('user')
	city = request.form.get('city')
	#city = city.decode('ascii').encode('gbk')
	city = city.decode('ascii', 'ignore').encode('utf-8')
	print city
	print chardet.detect(city) 
	date = "powershell set-aduser -identity %s -city %s" %(user,city)
	cmd = '"'+date+'"'
	result = os.system(cmd)
	return str(result)
@app.route('/get_lockedout', methods=['post','get'])
def get_lockedout():
	user = request.args.get('user')
	print user
	date = "powershell (Get-ADUser -Identity %s -Properties *).LockedOut" %(user)
	cmd = '"'+date+'"'
	print cmd
	result = os.popen(cmd).read()
	return result
@app.route('/get_messagestatu', methods=['post'])
def get_messagestatu():
	mailaddress = request.form.get('mailaddress')
	MessageSubject = request.form.get('MessageSubject')
	date = "Import-Module \\\\10.1.48.250\psm1\get-messagestatu.psm1;get-messagestatu -MailAddress %s -MessageSubject %s" %(mailaddress,MessageSubject)
	cmd = 'powershell "'+date+'"'
	print cmd
	result = os.popen(cmd).read()
	return result
@app.route('/get_system', methods=['get'])
def get_system(): 
	computername = request.args.get('computername')
	print computername
	date = u"powershell (Get-ADComputer -identity %s -Properties *).OperatingSystem" %(computername)
	cmd = '"'+date+'"'
	print cmd
	result = os.popen(cmd).read()
	return result.decode('gbk').encode('utf-8')
@app.route('/remove_user', methods=['get'])
def remove_user(): 
	user = request.args.get('user')
	date = "powershell Remove-ADUser -Identity %s -Confirm:$false" %(user)
	cmd = '"'+date+'"'
	print cmd
	result = os.system(cmd)
	result = result.decode('utf-8').encode('gbk')
	return str(result)
	
@app.route('/add_group', methods=['post'])
def add_group():
	user = request.form.get('user')
	if len(user) == 0:
		return "4003"
	group = request.form.get('group')
	if len(group) == 0:
		return "4004"
	date = "powershell Add-ADGroupMember -Identity %s -Members %s" %(group,user)
	cmd = '"'+date+'"'
	jieguo = os.system(cmd)
	if jieguo == 1:
		return "4005"
	result = os.system(cmd)
	return result	
@app.route('/liucheng_vpn', methods=['post','get'])
def liucheng_vpn():
	data= request.form.get('data')
	user_info = json.loads(data)
	
	for user in user_info:
		name = user["name"]
		to = "%s@lexinfintech.com" %(name)
		print to
		date = u"Send-MailMessage -SmtpServer 10.1.48.92 -Port 2525 -Subject 'vpn' -From mailadmin@lexinfintech.com -To %s -Body 'vpn' -Attachments D:\powershell\办公网VPN使用升级通知.msg" %(to)
		date2 = "add-adgroupmember -identity vpngroup -members %s" %(name)
		cmd = '"powershell '+date+'"'
		cmd2 = '"powershell '+date2+'"'
		print cmd
		print cmd2
		os.popen(cmd).read()
		result = os.system(cmd2)
		return str(result)
@app.route('/liucheng_weixin_type', methods=['post','get'])
def liucheng_weixin_type():
	alias = request.form.get('alias')
	to = "%s@lexinfintech.com" %(alias)
	tagname = request.form.get('tagname')
	token_all = requests_local.get('https://qyapi.weixin.qq.com/cgi-bin/gettoken?corpid=ww66c2305251a9903d&corpsecret=YNyM-NebYqGH1fBl4GIdCfUzm7a9wLefYL_NyrGmhJ8').text
	token = json_local.loads(token_all)['access_token']

	request_targe = 'https://qyapi.weixin.qq.com/cgi-bin/tag/list?access_token='+token
	targe_all = requests_local.get(request_targe).text
	print targe_all
	
	targe_text = json_local.loads(targe_all)['taglist']
	for i in targe_text:
		if i['tagname'] == tagname:
			tagid = i['tagid']
	headers = {'content-type': "application/json",}
	request_url='https://qyapi.weixin.qq.com/cgi-bin/tag/addtagusers?access_token='+token
	body = {"tagid": tagid , "userlist": [ to]}
	request_all = requests_local.post(request_url,data = json_local.dumps(body),headers = headers)
	request_text = request_all.text
	print request_text
	request_errcode = json_local.loads(request_text)['errcode']
	if str(request_errcode) == "0":
		userid = "bennyliu@lexinfintech.com|jadenzhang@lexinfintech.com"
		msg = u"申请流程: 企业微信应用可见范围<br>申请人: %s<br>申请应用: %s<br>申请成功: %s" %(alias,tagname,request_errcode)
		send_weixin8000(userid,msg)
		return "创建成功"
	else:
		userid = "bennyliu@lexinfintech.com|jadenzhang@lexinfintech.com"
		msg = u"申请流程: 企业微信应用可见范围<br>申请人: %s<br>申请应用: %s<br>申请失败: %s<br>" %(alias,tagname,request_errcode)
		send_weixin8000(userid,msg)
		return "创建失败"
	
@app.route('/liucheng_e_mail', methods=['post','get'])
def liucheng_e_mail():
	name = request.form.get('name')   #获取name参数---填写表单用户
	department = request.form.get('department') #获取department参数
	alias_all = request.form.get('alias') #获取alias参数--被审批的用户
	userid = "bennyliu@lexinfintech.com|jadenzhang@lexinfintech"
	if ';' in alias_all:
		alias_all = alias_all.split(';')
		for alias in alias_all:
			array = [
			]
			leader = request.form.get('leader') #获取leader参数--负责审批的用户
			data = 'powershell '+u"add-adgroupmember -identity 发外网邮件需要审批 -members %s" %(alias)  #定义加入到审批的安全组cmd命令
			data2 = 'powershell '+u"set-ADUser %s -Manager %s" %(alias,leader)  #定义设置上级的cmd命令
			cmd1 = data.encode('gbk')   #转成GBK格式
			cmd2 = data2.encode('gbk')  #转成GBK格式
			print cmd1
			print cmd2
			result1 = os.system(cmd1)  #传入到cmd运行并定义运行结果
			result2 = os.system(cmd2)  #传入到cmd运行并定义运行结果
			if result1 == 0:           #当第一条命令成功后，就执行下面命令
				if result2 == 0:       #当第二条命令成功后，就执行下面命令
					msg = u"申请流程: 外发邮件需要审批申请<br>申请人: %s<br>申请人部门: %s<br>被审批人: %s<br>负责审批人: %s <br>申请状态：成功>" %(name,department,alias,leader)   #定义企业微信告警消息内容
					send_weixin8000(userid,msg)	#发送企业微信告警消息内容
					data = [alias,leader,'OK']
					print data
					array.append(data)  #当第一和第二条命令同时成功就返回oK
				else :                 #第二条命令错误的话就执行
					msg = u"申请流程: 外发邮件需要审批申请<br>申请人: %s<br>申请人部门: %s<br>被审批人: %s<br>负责审批人: %s <br>申请状态：失败<br>失败原因: 设置上级不成功" %(name,department,alias,leader)	#定义企业微信告警消息内容
					send_weixin8000(userid,msg)	#发送企业微信告警消息内容
					data = [alias,leader,'设置上级不成功']
					array.append(data)#返回错误
			else :                     #第一条命令错误的话就执行
				msg = u"申请流程: 外发邮件需要审批申请<br>申请人: %s<br>申请人部门: %s<br>被审批人: %s<br>负责审批人: %s <br>申请状态：失败<br>失败原因: 加入 '发外网邮件需要审批' 安全组失败" %(name,department,alias,leader)  #定义企业微信告警消息内容
				send_weixin8000(userid,msg)	#发送企业微信告警消息内容
				data = [alias,leader,'用户未找到']         #返回错误
				array.append(data)#返回错误
		return "OK"
	else:
		alias = alias_all
		leader = request.form.get('leader') #获取leader参数--负责审批的用户
		data = 'powershell '+u"add-adgroupmember -identity 发外网邮件需要审批 -members %s" %(alias)  #定义加入到审批的安全组cmd命令
		data2 = 'powershell '+u"set-ADUser %s -Manager %s" %(alias,leader)  #定义设置上级的cmd命令
		cmd1 = data.encode('gbk')   #转成GBK格式
		cmd2 = data2.encode('gbk')  #转成GBK格式
		print cmd1
		print cmd2
		result1 = os.system(cmd1)  #传入到cmd运行并定义运行结果
		result2 = os.system(cmd2)  #传入到cmd运行并定义运行结果
		userid = "bennyliu@lexinfintech.com|jadenzhang@lexinfintech.com"
		if result1 == 0:           #当第一条命令成功后，就执行下面命令
			if result2 == 0:       #当第二条命令成功后，就执行下面命令
				msg = u"申请流程: 外发邮件需要审批申请<br>申请人: %s<br>申请人部门: %s<br>被审批人: %s<br>负责审批人: %s <br>申请状态：成功>" %(name,department,alias,leader)   #定义企业微信告警消息内容
				send_weixin8000(userid,msg)	#发送企业微信告警消息内容
				return "ok"        #当第一和第二条命令同时成功就返回oK
			else :                 #第二条命令错误的话就执行
				msg = u"申请流程: 外发邮件需要审批申请<br>申请人: %s<br>申请人部门: %s<br>被审批人: %s<br>负责审批人: %s <br>申请状态：失败<br>失败原因: 设置上级不成功" %(name,department,alias,leader)	#定义企业微信告警消息内容
				send_weixin8000(userid,msg)	#发送企业微信告警消息内容
				return "fail"      #返回错误
		else :                     #第一条命令错误的话就执行
			msg = u"申请流程: 外发邮件需要审批申请<br>申请人: %s<br>申请人部门: %s<br>被审批人: %s<br>负责审批人: %s <br>申请状态：失败<br>失败原因: 加入 '发外网邮件需要审批' 安全组失败" %(name,department,alias,leader)  #定义企业微信告警消息内容
			send_weixin8000(userid,msg)	#发送企业微信告警消息内容
			return "fail"          #返回错误
@app.route('/oa_auth', methods=['post','get'])
def oa_auth():
	text = request.form.get('text')
	print text
	key = request.form.get('key')
	print key
	obj = AES.new(key, AES.MODE_CBC, key) #使用AES-128 mode CBC加密,要求key为16位，明文要为16的倍数，不足16位倍数要补齐
	length = 16
	count = len(text)
	if count < length:
		add = (length-count)
		text = text + ('\0' * add)
	else:
		add = (length-(count % length))
		text = text + ('\0' * add)
	res= obj.encrypt(text)
	ret = base64.b64encode(res)
	return ret
	
@app.route('/liucheng_vid', methods=['post','get'])
def liucheng_vid():
	name = request.headers['Username']
	#name = request.form.get('name')
	to = "%s@lexinfintech.com" %(name)
	print to
	date = u"Send-MailMessage -SmtpServer 10.1.48.92 -Port 2525 -Subject '云桌面访问权限开通通知' -From 8000@lexinfintech.com -To %s,bennyliu@lexinfintech.com -Body '你好,请参考附件教程使用虚拟机' -Attachments D:\powershell\pvid.docx -Encoding utf8" %(to)
	date2 = "add-adgroupmember -identity VDIPool -members %s" %(name)
	cmd1 = u'powershell "'+date+'"'
	cmd1 = cmd1.encode('gbk')
	cmd2 = 'powershell "'+date2+'"'
	print cmd1
	print cmd2
	result2 = os.system(cmd2)
	result1 = os.system(cmd1)
	result = str(result1)+','+str(result2)
	return result
@app.route('/liucheng_mailapproval', methods=['post','get'])
def liucheng_mailapproval():
	#name = request.headers['Username']
	user = request.form.get('user')
	userleader = request.form.get('userleader')
	print user
	print userleader
	date = "Set-ADUser %s -Manager %s" %(user,userleader)

	date2 = "'Add-PSSnapin microsoft.exchange*';'Add-DistributionGroupMember -identity g_mail_manager@lexinfintech.com -members %s'" %(user)
	cmd2 = u'powershell "'+date+'"'
	cmd2 = cmd2.encode('gbk')
	cmd1 = 'powershell "'+date2+'"'
	print cmd1
	print cmd2
	result2 = os.system(cmd2)
	result1 = os.system(cmd1)
	result = str(result1)+','+str(result2)
	return result
@app.route('/liucheng_newuser', methods=['post','get'])
def liucheng_newuser():
	name = request.form.get('name')
	#name = name.encode('utf-8')
	email = request.form.get('alias')
	if 'lexinfintech.com' in email:
		alias = email.replace('@lexinfintech.com','')
	else:
		alias = email
	department = request.form.get('department')
	print alias
	admin = request.form.get('admin')
	admin = admin.encode('utf-8')
	to = "%s@lexinfintech.com" %(alias)
	to = to.encode('utf-8')
	toadmin = admin+'@lexinfintech.com'
	jieguodate = "powershell get-aduser -identity %s" %(alias)
	jieguocmd = '"'+jieguodate+'"'
	jieguo = os.system(jieguocmd)
	userid = "bennyliu@lexinfintech.com|jadenzhang@lexinfintech.com|v_vivainlai@lexinfintech.com"
	if jieguo == 1:
		#name = name.decode('utf-8').encode('gbk')
		print name
		date = u"New-ADUser -name %s -DisplayName %s -sAMAccountName %s -Description %s -userPrincipalName %s -ChangePasswordAtLogon $true" %(name,name,alias,admin,to)
		date = date.encode('gbk')
		print date
		date2 = u"Send-MailMessage -SmtpServer 10.1.48.92 -port 2525 -Subject '申请邮箱成功' -From mailadmin@lexinfintech.com -To %s -Encoding utf8 -Body '5分钟邮箱会开通，密码为Fenqile@123 登陆https://webmail.lexinfintech.com更改密码后才能使用'" %(toadmin)
		date2 = date2.encode('gbk')
		print date2
		date3 = u'dsquery user -samid %s|dsmod user -pwd Fenqile@123 -mustchpwd yes -acctexpires never -disabled no' %(alias)
		date3 = date3.encode('utf-8')
		print date3
		date4 = u"get-aduser -identity %s|Move-ADObject -TargetPath 'ou=特殊邮件用户,ou=乐信,dc=lexinfintech,dc=com'" %(alias)
		date4 = date4.encode('gbk')
		print date4
		cmd = 'powershell "'+date+'"'
		#cmd = cmd.encode('utf-8')
		print cmd
		cmd2 = 'powershell "'+date2+'"'
		#cmd2 = cmd2.encode('utf-8')
		print cmd2
		cmd4 = 'powershell "'+date4+'"'
		print cmd4
		result1 = os.system(cmd)
		result2 = os.system(cmd2)
		result3 = os.system(date3)
		result4 = os.system(cmd4)
		if result1 == 0:
			if result2 == 0:
				if result3 == 0:
					if result4 == 0:
						msg = u"申请流程: 公共邮箱申请<br>公共邮箱地址: %s<br>公共邮箱显示中文名: %s<br>申请人: %s<br>申请状态：成功<br>失败原因: 加入 '发外网邮件需要审批' 安全组失败" %(to,name,admin,department)
						send_weixin8000(userid,msg)	#发送企业微信告警消息内容
						return "OK"
					else:
						msg = u"申请流程: 公共邮箱申请<br>公共邮箱地址: %s<br>公共邮箱显示中文名: %s<br>申请人: %s<br>申请状态：失败<br>失败原因: 移动用户到 '特殊邮件用户OU'失败" %(to,name,admin,department)
						send_weixin8000(userid,msg)	#发送企业微信告警消息内容
						return "fail" 
				else:
					msg = u"申请流程: 公共邮箱申请<br>公共邮箱地址: %s<br>公共邮箱显示中文名: %s<br>申请人: %s<br>申请状态：失败<br>失败原因: 更改用户状态和密码 失败" %(to,name,admin,department)
					send_weixin8000(userid,msg)	#发送企业微信告警消息内容
					return "fail"
			else:
				msg = u"申请流程: 公共邮箱申请<br>公共邮箱地址: %s<br>公共邮箱显示中文名: %s<br>申请人: %s<br>申请状态：失败<br>失败原因: 发送邮件 失败" %(to,name,admin,department)
				send_weixin8000(userid,msg)	#发送企业微信告警消息内容
				return "fail"
		else:
			msg = u"申请流程: 公共邮箱申请<br>公共邮箱地址: %s<br>公共邮箱显示中文名: %s<br>申请人: %s<br>申请状态：失败<br>失败原因: 新建用户 失败" %(to,name,admin,department)
			send_weixin8000(userid,msg)	#发送企业微信告警消息内容
			return "fail"
	else:
		return "用户已存在"
@app.route('/set_mac', methods=['get'])
def set_mac():
	user = request.args.get('user')
	print user
	date = u"Add-ADGroupMember -Identity mac -Members %s" %(user)
	cmd = '"powershell '+date+'"'
	print cmd
	result = os.system(cmd)
	return str(result)

def send_weixin8000(userid,msg):
	token_all = requests_local.get('https://qyapi.weixin.qq.com/cgi-bin/gettoken?corpid=ww66c2305251a9903d&corpsecret=dPI9vCFpYZCWiZngW--8Sd-R9dc-2FSZE32_-_zHwP0').text
	token = json_local.loads(token_all)['access_token']
	headers = {'content-type': "application/json",}
	request_url='https://qyapi.weixin.qq.com/cgi-bin/message/send?access_token='+token
	body = {"touser": userid , "msgtype": "text" , "agentid": "1000016" , "text" : {"content" : msg} , "safe" : "0"}
	request_all = requests_local.post(request_url,data = json_local.dumps(body),headers = headers)
	request_text = request_all.text
	return request_text 
	
if __name__ == '__main__':
    app.run(host='0.0.0.0',port=85,debug = True)
	