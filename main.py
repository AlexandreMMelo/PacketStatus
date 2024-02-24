import tkinter
from threading import *
from tkinter import messagebox
from tkinter import ttk
from time import sleep
import socket
from scapy.all import sniff
import datetime
import json

UPDATE_DELAY = 1
LAST = 10
RUN_SNIFFER = False
INFO = None

def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(('8.8.8.8', 80))
        local_ip = s.getsockname()[0]
    finally:
        s.close()
    return local_ip


def setup():
    global INFO
    INFO = {
    'my_ip': get_local_ip(),
    'from_me':{
        'total': 0,
        'unique': {},
        'last':[]
    },
    'to_me':{
        'total': 0,
        'unique': {},
        'last':[]
    },
}

def sniffer():
    def packet_callback(packet):
        now = str(datetime.datetime.now())
        if packet.haslayer('IP') and (packet['IP'].src ==INFO['my_ip']):
            INFO['from_me']['total'] += 1
            if packet['IP'].dst not in INFO['from_me']['unique'].keys():
                INFO['from_me']['unique'][packet['IP'].dst] = {}
                INFO['from_me']['unique'][packet['IP'].dst]['packet'] = 1
                INFO['from_me']['unique'][packet['IP'].dst]['last_active'] = now
            else:
                INFO['from_me']['unique'][packet['IP'].dst]['packet'] += 1
                INFO['from_me']['unique'][packet['IP'].dst]['last_active'] = now
            if packet['IP'].dst not in INFO['from_me']['last']:
                if len(INFO['from_me']['last']) == LAST:
                    INFO['from_me']['last'].pop(0)
                INFO['from_me']['last'].append(packet['IP'].dst)
        
        elif packet.haslayer('IP') and (packet['IP'].dst ==INFO['my_ip']):
            INFO['to_me']['total'] += 1
            if packet['IP'].src not in INFO['to_me']['unique'].keys():
                INFO['to_me']['unique'][packet['IP'].src] = {}
                INFO['to_me']['unique'][packet['IP'].src]['packet'] = 1
                INFO['to_me']['unique'][packet['IP'].src]['last_active'] = now
            else:
                INFO['to_me']['unique'][packet['IP'].src]['packet'] += 1
                INFO['to_me']['unique'][packet['IP'].src]['last_active'] = now
            if packet['IP'].src not in INFO['to_me']['last']:
                if len(INFO['to_me']['last']) == LAST:
                    INFO['to_me']['last'].pop(0)
                INFO['to_me']['last'].append(packet['IP'].src)
        update(labelsInput,INFO['to_me']['last'])
        update(labelsOutput,INFO['from_me']['last'])
        update(labelsGeneral,INFO,general=True)
        if not RUN_SNIFFER:
            exit()
    
    sniff(filter='ip', prn=packet_callback)

def updater():
    update(labelsInput,INFO['to_me']['last'])
    update(labelsOutput,INFO['from_me']['last'])
    update(labelsGeneral,INFO,general=True)
    sleep(UPDATE_DELAY)
    
def threading():
    global RUN_SNIFFER
    if RUN_SNIFFER:
        RUN_SNIFFER = False
        button.config(text="Start SNIFFER")
    else:
        RUN_SNIFFER = True
        button.config(text="Stop SNIFFER")
        t1=Thread(target=sniffer) 
        t1.start()


def on_closing():
    global RUN_SNIFFER
    if messagebox.askokcancel("Quit", "Do you want to quit?"):
        RUN_SNIFFER = False
        window.destroy()

def update(labels,data,general=False):
    if general:
        labels[1].config(text='Total IP to input sniffed: '+str(len(INFO['to_me']['unique'])))
        labels[2].config(text='Total packet in input sniffed: '+str(INFO['to_me']['total']))
        labels[3].config(text='Total IP to output sniffed: '+str(len(INFO['from_me']['unique'])))
        labels[4].config(text='Total packet in input sniffed: '+str(INFO['from_me']['total']))
        labels[5].config(text='Total packet sniffed: '+str(INFO['to_me']['total']+INFO['from_me']['total']))
    else:
        for i in range(len(data)):
            labels[i+1].config(text='IP: '+str(data[i]))

def download():
    folder = '/'.join(__file__.split('/')[:-1])
    if messagebox.askokcancel("Save", f"Do you want to save in {folder}/outputs ?"):
        now = datetime.datetime.now().strftime('%d_%m_%Y_%H_%M_%S')
        try:
            with open(f'{folder}/output/{now}.json', '+w') as f:
                f.write(json.dumps(INFO,indent=4))
        except Exception as e:
            messagebox.showerror(f'Erro: {e}', message=f'erro ao salvar {folder}/output/{now}.json')
        else:
            messagebox.showinfo('Arquivo salvo', message=f'Dados salvo em: {folder}/output/{now}.json')


# define window
window = tkinter.Tk()
window.title("Network")
window.geometry('550x550')

style = ttk.Style(window)
style.configure('lefttab.TNotebook', tabposition='ne')

tab_control = ttk.Notebook(window,style='lefttab.TNotebook')

tab1 = tkinter.Frame(tab_control)
tab2 = tkinter.Frame(tab_control)
tab3 = tkinter.Frame(tab_control)

tab_control.add(tab1, text='Input')
tab_control.add(tab2, text='Output')
tab_control.add(tab3, text='General')


labelsInput = [tkinter.Label(tab1,text=f'The source ip of the latest {LAST} packets')]+[tkinter.Label(tab1,text='',anchor="w",justify="left",width=25) for x in range(LAST)]
for label in labelsInput:
    label.grid(pady=5)
    
labelsOutput = [tkinter.Label(tab2,text=f'The destination IP of the last {LAST} packets')]+[tkinter.Label(tab2,text='',anchor="w",justify="left",width=25) for x in range(LAST)]
for label in labelsOutput:
    label.grid(pady=5) 

labelsGeneral = [
    tkinter.Label(tab3,text='General info',anchor="w",justify="left",width=25),
    tkinter.Label(tab3,text='Total IP to input sniffed: ',anchor="w",justify="left",width=25),
    tkinter.Label(tab3,text='Total packet in input sniffed: ',anchor="w",justify="left",width=25),
    tkinter.Label(tab3,text='Total IP to output sniffed: ',anchor="w",justify="left",width=25),
    tkinter.Label(tab3,text='Total packet in input sniffed: ',anchor="w",justify="left",width=25),
    tkinter.Label(tab3,text='Total packet sniffed: ',anchor="w",justify="left",width=25),

    ]

for label in labelsGeneral:
    label.grid(pady=5)
download = tkinter.Button(tab3,text="Download Data",command=download ) 
download.grid(column=2,row=7)


button = tkinter.Button(window,text="Start SNIFFER",command = threading)
button.pack(anchor='e') 

tab_control.pack(expand=1, fill='both')
window.protocol("WM_DELETE_WINDOW", on_closing)
setup()
window.mainloop()