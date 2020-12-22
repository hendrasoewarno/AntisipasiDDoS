# IPTABLES
Pengendalian Server untuk membatasi serangan<br>
<br>
Beberapa contoh terkait dengan pemberdayaan iptables untuk membatasi koneksi ke server<br>
1. Menerima koneksi pada beberapa port
```
iptables -A INPUT -p tcp --match multiport --dports 80,22,53 -j ACCEPT
```
2. Menolak koneksi dari IP Address tertentu
```
iptables -A INPUT -s 192.168.252.12 -j DROP
```
3. Menolak koneksi dari MAC Address tertentu
```
iptables -A INPUT -m mac --mac-source 00:0F:EA:91:04:08 -j DROP
```
4. Menolak Ping pada interface tertentu
```
iptables -A INPUT -i eth1 -p icmp --icmp-type echo-request -j DROP
```
5. Menolak koneksi dari IP Address tertentu pada interface tertentu
```
iptables -A INPUT -i eth0 -s 192.168.252.12 -j DROP
```
6. Menolak lebih dari 150 koneksi ke Server
```
iptables -A INPUT -p tcp --syn -m connlimit --connlimit-above 150 -j REJECT --reject-with tcp-reset
```
7. Menolak lebih dari 15 koneksi untuk satu IP Address (ditunjukan oleh --connlimit-mask 32)
```
iptables -A INPUT -p tcp --syn -m connlimit --connlimit-above 15 --connlimit-mask 32 -j REJECT --reject-with tcp-reset
```
8. Menolak lebih dari 15 koneksi ke port 80 untuk satu IP Address (ditujukan oleh --dport 80)
```
iptables -A INPUT -p tcp --syn --dport 80 -m connlimit --connlimit-above 15 --connlimit-mask 32 -j REJECT --reject-with tcp-reset
```
9. Menolak lebih dari 15 koneksi ke port 80 untuk satu IP Address dengan pengecualian sumber koneksi dari 192.168.0.8 (ditunjukan oleh !-s 192.168.0.8)
```
iptables -A INPUT -p tcp !-s 192.168.0.8 --syn --dport 80 -m connlimit --connlimit-above 15 --connlimit-mask 32 -j REJECT --reject-with tcp-reset
```
# Syn Flood Attack (a.k.a Half Open Attack)
Merupakan salah satu modus DDoS serangan cepat yang bertujuan menghabiskan sumber daya koneksi TCP pada server, sehingga tidak dapat melayani koneksi lainnya. Pada koneksi normal klien akan mengajukan permintaan koneksi dengan mengirim paket SYN ke server, kemudian server mengenali permintaan ini dan mengirim SYN-ACK kembali ke klien dan menunggu jawaban ACK dari klien. Pada Syn Flood Attack klien mengirim banyak paket SYN tetapi tidak pernah merespon SYN-ACK, sehingga koneksi pada server menjadi gantung sampai timeout, sampai pada satu level server akan kehabisan sumber daya koneksi untuk melayani koneksi sah lainnya.<br>
1. Mengaktifkan syncookies pada file /etc/sysctl.d/10-network-security.conf
```
net.ipv4.tcp_syncookies=1
```
2. Menggunakan iptables untuk koneksi per IP Address.
```
#batasi semua paket baru yang tidak ada SYN
iptables -A INPUT -p tcp ! --syn -m state --state NEW -j DROP

iptables -N syn_flood
iptables -A INPUT -p tcp --syn -j syn_flood
iptables -A syn_flood -m limit --limit 1/s --limit-burst 3 -j RETURN
iptables -A syn_flood -j LOG --log-prefix "SYN flood: "
iptables -A syn_flood -j DROP –log-level 6
```
# Port Scanner
```
#batasi fragment package
iptables -A INPUT -f -j DROP

#batasi semua NULL SCAN
iptables -A INPUT -p tcp –tcp-flags ALL NONE -j LOG –log-prefix "NULL scan: "
iptables -A INPUT -p tcp –tcp-flags ALL NONE -j DROP

#batasi XMAS SCAN
iptables -A INPUT -p tcp –tcp-flags ALL ALL -j LOG –log-prefix "XMAS scan: "
iptables -A INPUT -p tcp –tcp-flags ALL ALL -j DROP
iptables -A INPUT -p tcp –tcp-flags ALL URG,PSH,FIN -j LOG –log-prefix "NMAP-XMAS scan: "
iptables -A INPUT -p tcp –tcp-flags ALL URG,PSH,FIN -j DROP

#batasi FIN SCAN
iptables -A INPUT -p tcp –tcp-flags ACK,FIN FIN -j LOG –log-prefix "FIN scan: "
iptables -A INPUT -p tcp –tcp-flags ACK,FIN FIN -j DROP
iptables -A INPUT -p tcp –tcp-flags ALL FIN -j LOG –log-prefix “FIN scan: ”
iptables -A INPUT -p tcp –tcp-flags ALL FIN -j DROP
iptables -A INPUT -p tcp –tcp-flags ALL SYN,FIN -j LOG –log-prefix "SYN-FIN scan: "
iptables -A INPUT -p tcp –tcp-flags ALL SYN,FIN -j DROP

#batasi ACK SCAN
iptables -A INPUT -p tcp –tcp-flags ACK,FIN FIN -j LOG –log-prefix "ACK FIN scan: "
iptables -A INPUT -p tcp –tcp-flags ACK,FIN FIN -j DROP
iptables -A INPUT -p tcp –tcp-flags ACK,PSH PSH -j LOG –log-prefix "ACK PSH scan: "
iptables -A INPUT -p tcp –tcp-flags ACK,PSH PSH -j DROP
iptables -A INPUT -p tcp –tcp-flags ACK,URG URG -j LOG –log-prefix "ACK URG scan: "
iptables -A INPUT -p tcp –tcp-flags ACK,URG URG -j DROP
```

sudo iptables -A INPUT -p tcp --tcp-flags ALL FIN,PSH,URG -m limit --limit 5/min -j LOG --log-prefix “<IPT> Xmas scan: “
