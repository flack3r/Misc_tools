from idaapi import *
import idc 

mark_list = []
def check_refs(fun, debug=1):
	addr = LocByName( fun )
	refs_list = []
	if addr != BADADDR:
			cross_refs = CodeRefsTo( addr, 0)
			if debug == 1:
				print "[*]refs to %s" %(fun)
				print "======================"
			for ref in cross_refs:
					if debug == 1:
						print "%08x" %(ref)
					refs_list.append(ref)
	return refs_list


def Mark(addr, find):
	global mark_list
	f = get_func(addr)
	if not f:
		print "[*]0x%x is not function" %(addr)
	fc = FlowChart(f)
	for block in fc:
		addr = block.startEA
		while True:
			arg_no = GetDisasm(addr).count(",")
			for i in range(arg_no+1):
				if GetOpnd(addr, i) == find:
					idc.SetColor(addr, CIC_ITEM, 0xffff00)
					mark_list.append(addr)

			if idc.NextHead(addr) > block.endEA:
					break
			addr = idc.NextHead(addr)

def MarkClear():
	global mark_list
	for addr in mark_list:
		idc.SetColor(addr, CIC_ITEM, 0xffffff)
	mark_list = []

def Check_get( fun ):
	refs_list = check_refs(fun,0)
	for refs in refs_list:
		flag = 0
		f = get_func(refs)
		if not f:
			continue
		fc = FlowChart(f)
		for block in fc:
			addr = block.startEA
			while True:
				arg_no = GetDisasm(addr).count(",")
				for i in range(arg_no+1):
					arg1 = GetOpnd(addr, i)
					if arg1 == 'req_get_cstream_var':
						flag = 1
						break
				if (idc.NextHead(addr) > block.endEA)or (flag == 1):
					break
				addr = idc.NextHead(addr)
			if flag == 1:
				break
		if flag == 1:
			print "[*]possible exploit refs 0x%x" %(refs)

def man():
	print "[1] def check_refs(fun_name) => check reference"
	print "[1] def Check_get(fun_name) => check req_get_cstream_var"
	print "[2] def Mark(addr, find_string) => marking argument"
	print "[3] def MarkClear() => Marking Clear"
	print "[*] manual: man()"

man()