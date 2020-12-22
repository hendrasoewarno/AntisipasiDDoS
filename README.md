# IPTABLES
Pengendalian Server untuk membatasi serangan<br>
<br>
1. Menolak lebih dari 15 koneksi ke port 80 untuk satu IP Address
```
iptables -A INPUT -p tcp --syn --dport 80 -m connlimit --connlimit-above 15 --connlimit-mask 32 -j REJECT --reject-with tcp-reset
```
2. Menolak lebih dari 15 koneksi ke port 80 untuk satu IP Address dengan pengecualian sumber koneksi dari 192.168.0.8
```
iptables -A INPUT -p tcp --syn --dport 80 -m connlimit --connlimit-above 15 --connlimit-mask 32 -j REJECT --reject-with tcp-reset
```
