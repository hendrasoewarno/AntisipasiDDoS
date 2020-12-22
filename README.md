# IPTABLES
Pengendalian Server untuk membatasi serangan<br>
<br>
Beberapa contoh terkait dengan pemberdayaan iptables untuk membatasi koneksi ke server<br>
1. Menolak koneksi dari IP Address tertentu
```
iptables -A INPUT -s 192.168.252.12 -j DROP
```
2. Menolak koneksi dari MAC Address tertentu
```
iptables -A INPUT -m mac --mac-source 00:0F:EA:91:04:08 -j DROP
```
3. Menolak koneksi dari IP Address tertentu pada interface tertentu
```
iptables -A INPUT -i eth0 -s 192.168.252.12 -j DROP
```
4. Menolak lebih dari 150 koneksi ke Server
```
iptables -A INPUT -p tcp --syn -m connlimit --connlimit-above 150 -j REJECT --reject-with tcp-reset
```
5. Menolak lebih dari 15 koneksi untuk satu IP Address (ditunjukan oleh --connlimit-mask 32)
```
iptables -A INPUT -p tcp --syn -m connlimit --connlimit-above 15 --connlimit-mask 32 -j REJECT --reject-with tcp-reset
```
6. Menolak lebih dari 15 koneksi ke port 80 untuk satu IP Address (ditujukan oleh --dport 80)
```
iptables -A INPUT -p tcp --syn --dport 80 -m connlimit --connlimit-above 15 --connlimit-mask 32 -j REJECT --reject-with tcp-reset
```
7. Menolak lebih dari 15 koneksi ke port 80 untuk satu IP Address dengan pengecualian sumber koneksi dari 192.168.0.8 (ditunjukan oleh !-s 192.168.0.8)
```
iptables -A INPUT -p tcp !-s 192.168.0.8 --syn --dport 80 -m connlimit --connlimit-above 15 --connlimit-mask 32 -j REJECT --reject-with tcp-reset
```
