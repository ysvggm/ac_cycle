#!/usr/bin/env python3
import subprocess
import sys
import argparse
import datetime
import time
import filecmp
import difflib
import os
import socket

PASS_BANNER = """
########     ###     ######   ######     #### ####
##     ##   ## ##   ##    ## ##    ##    #### ####
##     ##  ##   ##  ##       ##          #### ####
########  ##     ##  ######   ######      ##   ##
##        #########       ##       ##
##        ##     ## ##    ## ##    ##    #### ####
##        ##     ##  ######   ######     #### ####
"""

FAIL_BANNER = """
########    ###    #### ##          #### ####
##         ## ##    ##  ##          #### ####
##        ##   ##   ##  ##          #### ####
######   ##     ##  ##  ##           ##   ##
##       #########  ##  ##
##       ##     ##  ##  ##          #### ####
##       ##     ## #### ########    #### ####
"""
#===================================================================================
def Log(string):
	now = datetime.datetime.today()
	tmp = "[%04d/%02d/%02d %02d:%02d:%02d] %s\n"%(now.year, now.month, now.day, now.hour, now.minute, now.second, string)
	f = open("LOG.txt","a")
	f.write(tmp)
	f.close()
	print(string)
#===================================================================================
def Compare():
	Log("SYS Comparison!!")
	if(os.path.exists("SYS.txt") == False):
		return "Couldn't find SYS.txt"

	if(os.path.exists("SYS.new") == True):
		os.remove("SYS.new")

	Log("Create TEMP File for Comparison!! (SYS.new)")

	cmd1 = "lspci -vx | grep -a5 0073"
	ret1 = subprocess.check_output(cmd1, shell=True, universal_newlines=True)
	cmd2 = "./bam_rw_mem --RegBar=0xcfffc000 --TestType=info"
	ret2 = subprocess.check_output(cmd2, shell=True, universal_newlines=True)
	f = open("SYS.new","w")
	f.write(ret1)
	f.write(ret2)
	f.close()


	if(filecmp.cmp("SYS.txt","SYS.new") == False):
		return "SYS Comparison Fail\n" + File_Comp("SYS.txt","SYS.new")

	return 0
#===================================================================================
def File_Comp(a1,a2):
	f1 = open(a1,"r")
	f2 = open(a2,"r")
	r1 = f1.readlines()
	r2 = f2.readlines()
	f1.close()
	f2.close()

	for i in r1:
		i = i.strip()
	for i in r2:
		i = i.strip()

	d = difflib.Differ()
	result = list(d.compare(r1, r2))

	ret = ""

	for i in result:
		if(i[0] == '?'):
			continue
		ret = ret + i.strip() + "\n"

	return ret
#===================================================================================
def Execute():
	msg = b"#AAAA-000&"
	HOST = '192.168.127.254'
	PORT = 4001
	
	Log("Execute APCT-III Command via LAN (%s:%d)"%(HOST, PORT))
	
	'''
	COM = "COM8"
	s = serial.Serial(port = COM, baudrate = 9600, timeout = 5)
	s.write(msg)
	ret = s.readlines()
	print(ret)
	s.close()
	'''

	sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	
	try:
		sock.connect((HOST, PORT))
	except:
		return "LAN Connection Error!!"
	
	sock.sendall(msg)
	data = sock.recv(1024)
	sock.close()
	
	return 0
#===================================================================================
def Shutdown():
	Log("Shutdown System in 10 Seconds")

	for i in range(10):
		print("	%d..."%(10-i))
		time.sleep(1)

	ret = Execute()
	if(ret != 0):
		Log(ret)
	else:
		Log("Shutdown System!!")
		cmd = "/sbin/poweroff"
		ret = subprocess.call(cmd, shell=True, universal_newlines=True)
	
	return ret
#===================================================================================
def Update():
	f = open("CYCLE.txt","r+")
	tmp = int(f.read().strip(),10)
	f.seek(0)
	f.write(str(tmp+1))
	f.close()
#===================================================================================
def GetVal(filename):
	f = open(filename,"r")
	tmp = int(f.read().strip(),10)
	f.close()

	return tmp
#===================================================================================
def Remove():
	tmp_list = ["CYCLE.txt", "MAX.txt", "LOG.txt", "SYS.txt", "SYS.new"]
	
	for i in tmp_list:
		if(os.path.exists(i) == True):
			os.remove(i)
#===================================================================================
def Init():
	global args

	Remove()

	Log("AC Cycle Tool, by CESBG-TEC-SW")
	Log("Total Test Cycle: %d"%args.cycle)
	Log("Create INIT File for Comparison!! (SYS.txt)")


	f = open("CYCLE.txt","w")
	f.write(str(0))
	f.close()

	f = open("MAX.txt","w")
	f.write(str(args.cycle))
	f.close()

	cmd1 = "lspci -vx | grep -a5 0073"
	ret1 = subprocess.check_output(cmd1, shell=True, universal_newlines=True)
	cmd2 = "./bam_rw_mem --RegBar=0xcfffc000 --TestType=info"
	ret2 = subprocess.check_output(cmd2, shell=True, universal_newlines=True)
	
	f = open("SYS.txt","w")
	f.write(ret1)
	f.write(ret2)
	f.close()

	Log("Test Initialization Finish!!")
#===================================================================================
def End():
	Log("AC Test End")
	now = datetime.datetime.today()
	filename = "Log_%04d%02d%02d_%02d%02d%02d.txt"%(now.year, now.month, now.day, now.hour, now.minute, now.second)
	os.rename("LOG.txt",filename)
	Remove()
	print("Log Filename: %s"%(filename))
	input("Press Any Key to Continue...")
#===================================================================================
def main(argv):
	global args
	VER = "1.0"

	opts = argparse.ArgumentParser(description = "BAM AC Cycle Tool, by CESBG-TEC-SW\nVersion: %s"%VER, epilog = "Example: python3 BAM_AC_Cycle.py -c 500")
	group = opts.add_mutually_exclusive_group()
	opts.add_argument('-v', '--version', action = 'version', version = VER, help = "Show Version")
	group.add_argument('-c', '--cycle', type = int, required = False, default = 0, help = "Test Cycle")
	group.add_argument('-r', '--remove', action = "store_true", required = False, help = "Remove Template File")
	group.add_argument('-e', '--execute', action = "store_true", required = False, help = "Execute APCT-III Command")
	
	args = opts.parse_args()

	if(args.remove == True):
		Remove()
	elif(args.execute == True):
		ret = Execute()
		if(ret == 0):
			print("Pass")
		else:
			print("Fail: " + ret)
	elif(args.cycle > 0):
		Log("Test Cycle = %d"%(args.cycle))
		Init()
		ret = input("Shutdown System?? (Y/N)\n").strip().upper()
		if(ret == "Y" or ret == "YES"):
			Shutdown()
	elif(os.path.exists("CYCLE.txt") == True or os.path.exists("MAX.txt") == True):
		cycle = GetVal("CYCLE.txt")
		max = GetVal("MAX.txt")
		Log("Cycle[%d/%d]..."%(cycle,max))
		ret = Compare()
		if(ret == 0 and cycle < max):
			Log("Cycle[%d/%d]: Pass!!"%(cycle,max))
			Update()
			Shutdown()
		elif(ret == 0 and cycle == max):
			Log("Cycle[%d/%d]: Pass!!"%(cycle,max))
			Log("Test Pass!!")
			print(PASS_BANNER)
			End()
		elif(ret != 0):
			Log("Test Fail!! (Error Message: %s)"%(ret))
			print(FAIL_BANNER)
	else:
		opts.print_help()

	return
#===================================================================================
if __name__ == '__main__':
	main(sys.argv)
	sys.exit(0)
