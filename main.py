from kivy.uix.boxlayout import BoxLayout
from kivy.uix.label import Label
from kivy.uix.button import Button
from kivy.uix.textinput import TextInput
from kivy.lang import Builder
from kivy.app import App
import socket
from kivy.uix.popup import Popup
from tabnanny import verbose

from scapy.all import *
from kivy.uix.scrollview import ScrollView
from kivy.uix.screenmanager import ScreenManager, Screen
from subprocess import check_output
import threading

from scapy.layers.l2 import ARP, Ether
from kivy.uix.switch import Switch

Builder.load_file('design.kv')


class NetTool(App):
    def build(self):
        return sm


class Screen1(Screen):
    def __init__(self, **kwargs):
        super(Screen1, self).__init__(**kwargs)

        self.save_btn =self.ids['save_btn']
        self.iface_name = self.ids['iface_name']
        self.device_lbl = self.ids['device_lbl']
        self.client_box = self.ids['client_box']
        self.nodes = self.ids['nodes']
        self.scnLAN = self.ids['scnLAN']
        self.node_list = [] #append nodes in scroll view
        self.logos = [['Apple', 'iphone', 'mac', ' ipad'],['Android', ' nexus'],['windows', 'user', '192.168.225.154'],
                      ['jiofi.local.html', '192.168.225.1', 'Zte']
                      ]

    def run_ifconfig(self):
        ''' Function for ifconfig '''
        self.scnLAN.disabled = False

        try:

            self.ifconfig = subprocess.check_output(['ifconfig', self.iface_name.text])
            self.iface, self.my_ip, self.MAC, self.Bcast, self.NMask, self.ipv6 \
                = (self.ifconfig.split()[i] for i in (0, 6, 4, 7, 8, 11))

            self.device_lbl.text = ('[color=00ff00][i][b] My device [/b][/i][/color]' + '\n\n'
                                    + 'Interface: ' + '[color=00ff00]{0}[/i][/color]'.format(self.iface) +'\n\n'
                                    + 'IP: '+ '[color=00ff00]{0}[/i][/color]'.format(self.my_ip[5:]) + '\n\n'
                                    + 'Mac: ' + '[color=00ff00]{0}[/i][/color]'.format(self.MAC) + '\n\n'
                                    + 'Bcast :' + '[color=00ff00]{0}[/i][/color]'.format(self.Bcast[6:]) + '\n\n'
                                    + 'Nmask: ' + '[color=00ff00]{0}[/i][/color]'.format(self.NMask[5:]) + '\n\n'
                                    + 'ipv6: ' + '[color=00ff00]{0}[/i][/color]'.format(self.ipv6) +'\n\n')

        except:
            pass

    def ARPscan(self):
        self.save_btn.disabled = False
        self.nodes.clear_widgets()
        self.node_list = [ ] # reset list on every arp scan
        #ip = '192.168.225.'

        for i in xrange(255):
            if i == 154:
                continue
            scanNode = ARPthread(i, self.nodes, self.iface_name.text,
                                 self.node_list, self.logos) #create thread
            scanNode.start() #start thread
            print 'Started threas: %s' %i


    def timeDate(self):
        now = time.localtime(time.time())
        return time.asctime(now) # get the date and tirmre



    def saveFile(self, i):
        print "HA"
        f = open(self.tinput.text + '.txt', 'w') # 'a' means append
        f.write('[] LAN Scan [] \n\n'+ self.timeDate() + '\n\n' +
                 '%s Hosts Up! \n\n' %len(self.node_list) )

        for i in self.node_list:
            f.write('IP: '+ i.psrc + '\n'+
                    'MAC: ' + i.hwsrc + '\n\n')

        f.close()
        self.lbl.text = 'File Saved!'


    def saveResults(self):
        self.box = BoxLayout(orientation='vertical')
        self.tinput = TextInput(text='file') # Ns=ame of file
        self.save_file_btn = Button(text= 'Save File!', on_press=self.saveFile) # Btn to save file
        self.lbl = Label(text='') #lbl to display users file is saved

        self.box.add_widget(self.tinput)
        self.box.add_widget(self.save_file_btn)
        self.box.add_widget(self.lbl)

        #Create a popup
        self.pop = Popup(content = self.box, title = 'Save Scan Results',
                         size_hint=(1, .5))

        self.pop.open()

    def change_screen(self):
        sm.current = 'Screen2'










class ARPthread(threading.Thread):
    '''threaded arp scan'''
    def __init__(self, ip, nodes, iface, node_list, logos):
        self.logos = logos
        self.node_list = node_list
        self.ip = ip #host ip
        self.nodes = nodes #scrolview
        self.iface = iface
        threading.Thread.__init__(self)

    def run(self):
        arpRequest = Ether(dst='ff:ff:ff:ff:ff:ff')/ARP(pdst='192.168.225.' + str(self.ip), hwdst='ff:ff:ff:ff:ff:ff')

        arpResponse = srp1(arpRequest, timeout=2, verbose=0, iface=self.iface)
        #print arpResponse == None, i
        if arpResponse != None:
            self.node_list.append(arpResponse) #add node to list
            print "yes"
            try:
                hostname = socket.gethostbyaddr(arpResponse.psrc)[0]
                print type(socket.gethostbyaddr(arpResponse.psrc))
                print hostname
            except:
                pass

            choose_button = ''
            for e in self.logos:
                for make in e:
                    if make.lower() in hostname:
                        choose_button = e[0]

            if choose_button == 'Android':
                self.nodes.add_widget(Button(text='[color=00ff00][i]Host is up[/i][/color]'.format(hostname) +
                                                  '\n[color=00ff00] IP: {0}[/color]'.format(arpResponse.psrc) +
                                                  '\n[color=00ff00] MAC: {0}[/color]'.format(arpResponse.hwsrc)
                                             , markup=True, font_size='15sp', height='150sp',
                                             background_normal='images/androidNode.png', valign='middle',
                                             halign='center', on_press=Screen1.change_screen))
            elif choose_button == 'Apple':
                self.nodes.add_widget(Button(text='[color=00ff00][i]Host is up[/i][/color]'.format(hostname) +
                                                  '\n[color=00ff00] IP: {0}[/color]'.format(arpResponse.psrc) +
                                                  '\n[color=00ff00] MAC: {0}[/color]'.format(arpResponse.hwsrc)
                                             , markup=True, font_size='15sp', height='150sp',
                                             background_normal='images/appleNode.png', valign='middle',
                                             halign='center', on_press=Screen1.change_screen))
            elif choose_button == 'Windows':
                self.nodes.add_widget(Button(text='[color=00ff00][i]Host is up[/i][/color]'.format(hostname) +
                                                  '\n[color=00ff00] IP: {0}[/color]'.format(arpResponse.psrc) +
                                                  '\n[color=00ff00] MAC: {0}[/color]'.format(arpResponse.hwsrc)
                                             , markup=True, font_size='15sp', height='150sp',
                                             background_normal='images/windowsNode.png', valign='middle',
                                             halign='center', on_press=Screen1.change_screen))
            elif choose_button == 'Linux':
                self.nodes.add_widget(Button(text='[color=00ff00][i]Host is up[/i][/color]'.format(hostname) +
                                                  '\n[color=00ff00] IP: {0}[/color]'.format(arpResponse.psrc) +
                                                  '\n[color=00ff00] MAC: {0}[/color]'.format(arpResponse.hwsrc)
                                             , markup=True, font_size='15sp', height='150sp',
                                             background_normal='images/linuxNode.png', valign='middle',
                                             halign='center', on_press=Screen1.change_screen))
            elif choose_button== 'jiofi.local.html':
                self.nodes.add_widget(Button(text='[color=00ff00][i]Host is up[/i][/color]'.format(hostname) +
                                                  '\n[color=00ff00] IP: {0}[/color]'.format(arpResponse.psrc) +
                                                  '\n[color=00ff00] MAC: {0}[/color]'.format(arpResponse.hwsrc)
                                             , markup=True, font_size='15sp', height='150sp',
                                             background_normal='images/gatewayNode.png', valign='middle',
                                             halign='center', on_press=Screen1.change_screen))
            elif choose_button == '':
                self.nodes.add_widget(Button(text='[color=00ff00][i]Host is up[/i][/color]'.format(hostname) +
                                                  '\n[color=00ff00] IP: {0}[/color]'.format(arpResponse.psrc) +
                                                  '\n[color=00ff00] MAC: {0}[/color]'.format(arpResponse.hwsrc)
                                             , markup=True, font_size='15sp', height='150sp',
                                             background_normal='images/unknownNode.png', valign='middle',
                                             halign='center', on_press=Screen1.change_screen))

        self.nodes.height = len(self.node_list*150)


class Screen2(Screen):
    def __init__(self, **kwargs):
        super(Screen2, self).__init__(**kwargs)

    def main_screen(self):
        sm.current = 'Screen1'



sm = ScreenManager()

sm.add_widget(Screen1(name='Screen1'))
sm.add_widget(Screen2(name='Screen2'))

if __name__ == '__main__':
    NetTool().run()
