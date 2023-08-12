# send_arp

attacker, victim, target을 두고 서로 다른 환경에서 ARP Spoofing 실습 진행

## ARP Spoofing

### Scinario chart:
![image](https://github.com/goei300/send_arp/assets/107453711/5bdca828-7366-4290-86db-6aa23ec90a45)


## VMWARE Conf

![image](https://github.com/goei300/send_arp/assets/107453711/4277cfd2-c552-4962-b2a0-448a3400945f)

vmware Ip: 10.1.1.97

vmware MAC : 00:0c:29:5b:ac:f9
## Phone Conf

### Ping Lite
Ping lite 앱을 통해 vmware에 ICMP 패킷 전송

<img src="https://github.com/goei300/send_arp/assets/107453711/e46d4185-2c89-4a0e-8231-16055c236935"
  width="200" height="400"/>


VMWare에서 wireshark 등 패킷 툴을 통해 phone ip 주소 확인

![image](https://github.com/goei300/send_arp/assets/107453711/ba3921f4-e1ae-4fc4-b120-b030ade8ede6)

--> Phone의 ip 주소 : 10.1.1.104


## Spoofing

코드 실행 후 phone에서 gateway로 ping을 통해 패킷 전송


![image](https://github.com/goei300/send_arp/assets/107453711/bf1fbe97-f9d0-48a9-82c0-f0b11b1e2d82)

 --> ARP Spoofing 성공


 # Arp-spoofing && Relay


 arp spoofed된 sender가 recover되는 시점을 확인 한 후,
실시간으로 sender를 재감염 시키고 sender로 부터 오는 arp-spoofed packet을 relay 한다.
추가로 sender-target 1쌍이 아닌 2쌍 이상의 여러 flow로 구현하도록 한다.

## Chart


## scenario

sender : 10.1.1.38
target : 10.1.1.1

sender : 10.1.1.1
target : 10.1.1.38

2 flows 

![image](https://github.com/goei300/send_arp/assets/107453711/43f0c829-a0df-488d-98c5-0245482ef6ed)



## Outcome

![image](https://github.com/goei300/send_arp/assets/107453711/b8345610-b28c-4256-add0-76efbadf0aff)

relay시 attacker의 네트워크에는 
sender로부터 arp-spoofed packet, 직접 relay하는 패킷 두 패킷이 캡쳐되어야한다.


![image](https://github.com/goei300/send_arp/assets/107453711/fdabb7cb-8d67-46fb-a19b-c86767d5a4fb)


![image](https://github.com/goei300/send_arp/assets/107453711/ff6b78fb-6c6b-4eec-91aa-759c82351b0b)

![image](https://github.com/goei300/send_arp/assets/107453711/e624ff3c-d38f-4ae0-901c-b33a6960f531)

![image](https://github.com/goei300/send_arp/assets/107453711/bbd68ba6-8f32-4e75-994c-cd19c000c4f5)

![image](https://github.com/goei300/send_arp/assets/107453711/e15372a1-9398-41b2-83b9-e881be409d5d)

# ping lite


<img src="https://github.com/goei300/send_arp/assets/107453711/b6905f0c-ab05-4631-ae32-5cf38034117d"
  width="600" height="600"/>




