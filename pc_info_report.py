import subprocess as sp
#from winrm.protocol import Protocol
import winrm
import re
from pprint import pprint
import psycopg2
'''
Get-MPComputerStatus -ErrorAction SilentlyContinue    
Get-MpThreat -ErrorAction SilentlyContinue
Get-WmiObject -Namespace root\SecurityCenter2 -Class AntiVirusProduct
Get-Service -Name "WinDefend"
Get-WmiObject -Class Win32_OperatingSystem
'''

def set_pc_error(pc):
    try:
        connect_str = "dbname='' user='postgres' host='localhost' " + \
                      "password=''"
        # use our connection values to establish a connection
        conn = psycopg2.connect(connect_str)
        # create a psycopg2 cursor that can execute queries
        cursor = conn.cursor()
        #pc_number,location,ip_address,cpu,motherboard,ram,storage,av_last_quickscan,av_last_fullscan,detection
        sql = "INSERT INTO computers (pc_number,location,ip_address,error) VALUES ('%i','%i','%s','%s');" % (pc['pc_number'],pc['location'],pc['ip_address'],pc['error'])
        cursor.execute(sql)
        conn.commit()
        return True
    except Exception as e:
        print("Uh oh, can't connect. Invalid dbname, user or password?")
        print(e) 
    
def set_pc_info(pc):
    try:
        connect_str = "dbname='' user='postgres' host='localhost' " + \
                      "password=''"
        # use our connection values to establish a connection
        conn = psycopg2.connect(connect_str)
        # create a psycopg2 cursor that can execute queries
        cursor = conn.cursor()
        #pc_number,location,ip_address,cpu,motherboard,ram,storage,av_last_quickscan,av_last_fullscan,detection
        sql = "INSERT INTO computers (pc_number,location,ip_address,cpu,motherboard,ram,gpu,storage,av_status,av_last_quickscan,av_last_fullscan,detection) VALUES ('%i','%i','%s','%s','%s','%s','%s','%s','%s','%s','%s','%s');" % (pc['pc_number'],pc['location'],pc['ip_address'],pc['cpu'],pc['motherboard'],pc['ram'],pc['gpu'],pc['storage'],pc['av_status'],pc['av_last_quickscan'],pc['av_last_fullscan'],pc['detection'])
        cursor.execute(sql)
        conn.commit()
        return True
    except Exception as e:
        print("Uh oh, can't connect. Invalid dbname, user or password?")
        print(e) 
    

def ipcheck(ip,pc_number):
    status,result = sp.getstatusoutput("ping -c1 -w2 " + str(ip))
    if status == 0:
        
        # win def threads
        ps_script9  = """Get-MpThreat -ErrorAction SilentlyContinue"""
        
        # win defender full last run
        ps_script8  = """Get-MPComputerStatus | Select-Object -Property FullScanEndTime"""
        
        # win defender quick last run
        ps_script7  = """Get-MPComputerStatus | Select-Object -Property QuickScanEndTime"""
        
        # win def status
        ps_script6  = """Get-Service -Name 'WinDefend'"""
        
        # monitor
        #ps_script = """ gwmi WmiMonitorID -Namespace root\wmi | ForEach-Object {($_.UserFriendlyName -notmatch 0 | foreach {[char]$_}) -join ""; ($_.SerialNumberID -notmatch 0 | foreach {[char]$_}) -join ""} """
        # storage
        ps_script5  = """wmic diskdrive get model"""
        # video card
        ps_script4 = """ Get-WmiObject Win32_VideoController -Property VideoProcessor"""
        # ram
        ps_script3 = """ Get-WmiObject Win32_PhysicalMemory  -Property Manufacturer,Capacity,DeviceLocator,Speed """
        # motherboard
        #ps_script = """ wmic baseboard get product,Manufacturer,version,serialnumber """
        ps_script2 = """Get-ComputerInfo -Property CsModel"""
        # processors 
        ps_script1 = """Get-ComputerInfo -Property CsProcessors"""
        try:
            s = winrm.Session(ip, auth=('Administrator', ''))
            r = s.run_ps("""ls""")
            computer = {}
            computer["ip_address"] = ip
            computer["pc_number"] = pc_number
            computer["location"] = 0
            # CPU
            try:
                r = s.run_ps(ps_script1)
                output1 = r.std_out.decode("utf-8") 
                result1 = re.search('{(.*)}', output1)
                print(output1.splitlines()[3].replace('{', '').replace('}', ''))
                computer["cpu"] = output1.splitlines()[3].replace('{', '').replace('}', '')
            except Exception as e:
                print(e)
                print("error: %s" % ip)
                pass
            # motherboard    
            try:
                r = s.run_ps(ps_script2)
                output2 = r.std_out.decode("utf-8") 
                result2 = re.search('{(.*)}', output2)
                print(output2.splitlines()[3])
                computer["motherboard"] = output2.splitlines()[3].replace('{', '').replace('}', '')
            except Exception as e:
                print(e)
                print("error: %s" % ip)
                pass
            # RAM    
            try:
                r = s.run_ps(ps_script3)
                output3 = r.std_out.decode("utf-8")
                readout = ""
                for line in output3.splitlines():
                    item = line.split(':')
                    
                    if "_" not in item[0]:
                        if "Capacity" in item[0].strip():
                            print(item[0].strip() + " : " + str(int(item[1])/1073741824) + "GB")
                            readout = readout + item[0].strip() + " : " + str(int(item[1])/1073741824) + "GB"
                        else:
                            print(line.strip())
                            readout = readout + line.strip()
                computer["ram"] = readout
                # ram 1073741824
            except Exception as e:
                print(e)
                print("error: %s" % ip)
                pass
            # GPU    
            try:
                r = s.run_ps(ps_script4)
                output4 = r.std_out.decode("utf-8")
                readout = ""
                for line in output4.splitlines():
                    item = line.split(':')
                    if "_" not in item[0]:
                        print(line.strip())
                        readout = readout + line.strip() 
                computer["gpu"]=readout
            except Exception as e:
                print(e)
                print("error: %s" % ip)
                pass
            # Storage    
            try:
                r = s.run_ps(ps_script5)
                output5 = r.std_out.decode("utf-8")
                for line in output5.splitlines():
                    print(line)
                computer["storage"] =  output5
            except Exception as e:
                print(e)
                print("error: %s" % ip)
                pass      
            # AV status   
            try:
                r = s.run_ps(ps_script6)
                output6 = r.std_out.decode("utf-8")
                status = output6.find("Running")
                if status != -1:
                    print("defender is running")
                    computer["av_status"] = "Running"
                else:
                    print("defender is not running")
                    computer["av_status"] = "Stopped"
            except Exception as e:
                print(e)
                print("error: %s" % ip)
                pass   
            # last scan quick scan
            try:
                r = s.run_ps(ps_script7)
                output7 = r.std_out.decode("utf-8")
                if not output7.splitlines()[3].strip():
                    print("No Quick Scan Done")
                    computer["av_last_quickscan"] = "None"
                else: 
                    print(output7.splitlines()[3])
                    computer["av_last_quickscan"] = output7.splitlines()[3]
            except Exception as e:
                print(e)
                print("error: %s" % ip)
                pass
            # last scan full scan
            try:
                r = s.run_ps(ps_script8)
                output8 = r.std_out.decode("utf-8")
                if not output8.splitlines()[3].strip():
                    print("No Full Scan Done")
                    computer["av_last_fullscan"] = "None"
                else:
                    print(output8.splitlines()[3])
                    computer["av_last_fullscan"] = output8.splitlines()[3]
                
            except Exception as e:
                print(e)
                print("error: %s" % ip)
                pass
            # threats
            try:
                r = s.run_ps(ps_script9)
                output9 = r.std_out.decode("utf-8")
                if not output9.splitlines():
                    print("No Threats Found")
                    computer["detection"] = "No Threats Found"
                else:
                    print(output9.splitlines())
                    computer["detection"] = output9.splitlines()[3]
            except Exception as e:
                print(e)
                print("error: %s" % ip)
                pass
                
            # final tally
            set_pc_info(computer)
                
        except Exception as e:
            print(e)
            print("error: %s" % ip)        
            computer={"pc_number":pc_number,"location":0,"ip_address":ip,"error":e}
            set_pc_error(computer)
            pass
            
        '''print("System " + str(ip) + " is UP !")
        ep = 'http://%s:5985/wsman' % str(ip)
        p = Protocol(
            endpoint=ep,
            transport='ntlm',
            username=r'.\Administrator',
            password='',
            server_cert_validation='ignore')
        try:
            shell_id = p.open_shell()
            command_id = p.run_command(shell_id, 'winrm set winrm/config/service @{AllowUnencrypted="true"}','')
            std_out, std_err, status_code = p.get_command_output(shell_id, command_id)
            print(std_out)
            p.cleanup_command(shell_id, command_id)
            p.close_shell(shell_id)
        except Exception as e:
            print(e)
            print(ip)
            pass'''
        
        
    else:
        print("System " + str(ip) + " is DOWN !")
        computer={"pc_number":pc_number,"location":0,"ip_address":ip,"error":"DOWN"}
        set_pc_error(computer)

for x in range(10, 41):
    #pc_number
    y = x - 9
    ipcheck('192.x.x.%i' % x, y)