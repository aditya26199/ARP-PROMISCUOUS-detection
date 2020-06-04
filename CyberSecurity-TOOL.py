from tkinter import * 
from tkinter import messagebox
from tkinter import ttk
from scapy.all import *
import PIL
from PIL import ImageTk
from PIL import Image
import threading
root = Tk() 
root.title("Detector 007")
t=threading.Event()

#starting of arp code
def danger(a): 
    global danger 
    danger=ImageTk.PhotoImage(Image.open("danger.png"))
    Z=Label(frame_b3,image=danger)
    Z.place(relx=0.05,rely=0.21) 
    lb1=Label(frame_b3,text="[!] you are under attack,REAL-MAC: "+str(a[0])+",\n FACE MAC:"+str(a[1]),fg="black").place(relx=0.05,rely=0.85)
    
#function if no spoofing is taking place 
def safe(): 
    global safe
    #print("safe")
    safe=ImageTk.PhotoImage(Image.open("safe.jpeg"))
    Z=Label(frame_b3,image=safe)
    Z.place(relx=0.05,rely=0.30) 
    lb1=Label(frame_b3,text="you are safe",fg="black").place(relx=0.05,rely=0.90)
#function getting mac addrees by broadcasting the ARP msg packets 
def get_macarp(ip): 
    print("mac")
    """ 
    Returns the MAC address of `ip`, if it is unable to find it 
    for some reason, throws `IndexError` 
    """ 
    p = Ether(dst="FF:FF:FF:FF:FF:FF")/ARP(pdst=ip) 
    result = srp(p, timeout=3, verbose=False)[0] 
    return result[0][1].hwsrc 
#process for every packet received by sniff function 
def process(packet): 
    #print("process")
    # if the packet is an ARP packet 
    global arpcount 
    if packet.haslayer(ARP): 
        # if it is an ARP response (ARP reply) 
        if packet[ARP].op == 2: 
            a=[]	 
            try: 
                # get the real MAC address of the sender 
                real_mac = get_macarp(packet[ARP].psrc) 
                #print(real_mac) 
                # get the MAC address from the packet sent to us 
                response_mac = packet[ARP].hwsrc 
                #print(response_mac) 
                # if they're different, definetely there is an attack 
                if real_mac != response_mac: 
                    #print(f"[!] You are under attack, REAL-MAC: {real_mac.upper()}, FAKE-MAC: {response_mac.upper()}") 
                    a.append(real_mac) 
                    a.append(response_mac) 
                    t.set()  #to stop the sniff function which is in thread  
                    return danger(a) 
                else: 
                    arpcount=arpcount+1 
                if arpcount == 40: 
                    t.set() 
                    return safe() 
            except IndexError: 
            	 
                # unable to find the real mac 
                # may be a fake IP or firewall is blocking packets 
                pass 
def arpcheck(t): 
    #print("arpcheck") 
    interface=iface.get() 
    sniff(store=False,prn=process,iface=interface,stop_filter=lambda x:t.is_set()) 
 
def arp(): 
    #print('arp')
    threading.Thread(target=arpcheck,args=(t,)).start() 
#end of arp code 

#below function are for promiscuous mode detection

def pro_mac(ip):
    #print("you're in pro_mac")
    a=Ether(dst="FF:FF:FF:FF:FF:FE")/ARP(pdst=ip)
    result = srp(a,timeout=3,verbose=False)[0]
    return result[0][1].hwsrc
    
def pro_start(ip):
    global img
    print("you're in opro start")
    try:
        result=pro_mac(ip)
        img=ImageTk.PhotoImage(Image.open("danger.png"))
        label2=Label(frame_b3,image=img)
        label2.place(relx=0.05,rely=0.21)
        label3=Label(frame_b3,text="The ip " + iface.get()+ " is in promiscuous mode")
        label3.place(relx=0.05,rely=0.89)   
    except:
        img=ImageTk.PhotoImage(Image.open("safe.jpeg"))
        label2=Label(frame_b3,image=img)
        label2.place(relx=0.05,rely=0.30)
        label3=Label(frame_b3,text="The ip " + iface.get()+ " is not in promiscuous mode")
        label3.place(relx=0.05,rely=0.90)             
        

	
	
# below functions are used for designing the tool for UI 


def go(x):
    if x==1:
        arp()
    else:
        pro_start(iface.get())
def reset():
    try:
        frame_b3.destroy()
    except:
        messagebox.showerror("ERROR","You haven't runned any action")

def inputdestroy():
    try:
        iface.delete(first=0,last=10)
    except:
        messagebox.showerror("ERROR","You haven't runned any action")
    
def confirm(x):
    global frame_b3
    frame_b3=LabelFrame(frame_right, bg="grey")
    frame_b3.place(relx=0.02, rely=0.02, relwidth=0.9, relheight=0.98)
    C=Label(frame_b3,text="Start detection ?").place(relx=0.05,rely=0.03)
    button1=Button(frame_b3,text="Yes",width=5,height=1,command=lambda:go(x)).place(relx=0.05,rely=0.11)
    button2=Button(frame_b3,text="No",width=5,height=1,command=reset).place(relx=0.30,rely=0.11)
    button3=Button(frame_b3,text="reset",width=5,height=1,command=inputdestroy).place(relx=0.55,rely=0.11)



def output(x):
	global iface
	global B
	global button
	global button4
	try:
	    B.destroy()
	    button.destroy()
	    button4.destroy()
	except:
	    pass
	if x == 'ARP Detection':
		B=Label(frame_b1,text="Enter the interface:")
		B.place(relx=0.05,rely=0.02)
		iface = Entry(frame_b1)
		iface.place(relx=0.05,rely=0.08)
		button = Button(frame_b1,text="Submit",command=lambda:confirm(1))
		button.place(relx=0.45,rely=0.07)
	elif x == 'Promiscuous Mode':
		B=Label(frame_b1,text="Enter the IP Address:")
		B.place(relx=0.05,rely=0.02)
		iface = Entry(frame_b1)
		iface.place(relx=0.05,rely=0.08)
		button4= Button(frame_b1,text="Submit",command=lambda:confirm(2))
		button4.place(relx=0.45,rely=0.07)
	else:
		messagebox.showerror("WARNING","Select valid option")

def fun():
    global A
    try:
        A.destroy()
    except:
        pass
    A = Label(main_frame,text="you have selected \n" + combo.get())
    A.place(relx=0.05,rely=0.35)
    var=combo.get()
    return output(var)
	
def info():
	messagebox.showinfo("Info!","Starting in a few seconds")

canvas = Canvas(root, width=700, height=500)  
canvas.pack()
main_frame =Frame(root, bg="gray")
main_frame.place(relx=0.05, rely=0.05, relwidth=0.9, relheight=0.9)

status = Label(root,text="ver-1.0")
status.pack()


label2=Label(main_frame, text="Select the option: ",bg="grey").place(relx=0.05,rely=0.03)

combo = ttk.Combobox(main_frame,values=[
	"None",
	"ARP Detection",
	"Promiscuous Mode"])
combo.place(relx=0.07,rely=0.14,relheight=0.05,relwidth=0.25)

con=Button(main_frame,text="Confirm",command=fun).place(relx=0.08,rely=0.24)

frame_div =Frame(root, bg="white")
frame_div.place(relx=0.35, rely=0.05, relwidth=0.4, relheight=0.9)

frame_b1 =Frame(root, bg="grey")
frame_b1.place(relx=0.36, rely=0.05, relwidth=0.6, relheight=0.9)

frame_b2 =Frame(root, bg="white")
frame_b2.place(relx=0.36, rely=0.20, relwidth=0.6, relheight=0.7)

frame_right=Frame(root, bg="grey")
frame_right.place(relx=0.36, rely=0.21, relwidth=0.6, relheight=0.7)


arpcount=0
root.mainloop()
