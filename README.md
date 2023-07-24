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
