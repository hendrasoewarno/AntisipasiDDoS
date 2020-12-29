# Menangani  Distributed Denial of Service (DDoS) dan Port Scanner
Pengendalian Server untuk membatasi serangan DDos adalah penting, tetapi secara umum serangan DDoS adalah sulit untuk ditangani, karena menyangkut kepada layanan dari server, terutama serangan DDoS pada layer aplikasi. Pada tulisan ini adalah membahas terkait dengan menangani Flooding pada Port, UDP dan ICMP.<br>
<br>
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

#https://www.researchgate.net/publication/265181297_Mitigating_DoSDDoS_attacks_using_iptables
#SYN FLOOD
iptables -N syn_flood
iptables -A INPUT -p tcp --syn -j syn_flood
iptables -A syn_flood -m limit --limit 1/s --limit-burst 3 -j RETURN
iptables -A syn_flood -j LOG --log-prefix "SYN flood: "
iptables -A syn_flood -j DROP

#UDP FLOOD
ptables -N udp_flood  
iptables -A INPUT -p udp -j udp_flood  
iptables -A udp_flood -m state –state NEW –m recent –update –seconds 1 –hitcount 10 -j RETURN  
iptables -A syn_flood -j LOG --log-prefix "UDP flood: "
iptables -A udp_flood -j DROP

#ICMP FLOOD
iptables -N icmp_flood  
iptables -A INPUT -p icmp -j icmp_flood  
iptables -A icmp_flood -m limit --limit 1/s --limit-burst 3 -j RETURN
iptables -A icmp_flood -j DROP
```
# Port Scanner
Port Scanner merupakan aktvitas untuk mendapatkan informasi terkait dengan Open Port, Closed Port, dan Filtered Port.<br>
```
#batasi fragment package
iptables -A INPUT -f -j DROP

#membuat LOG SCAN DROP 
iptables -N port_scan
iptables -A port_scan -j LOG --log-prefix "Port Scanner: "
iptables -A port_scan -j DROP

#batasi semua NULL SCAN
iptables -A INPUT -p tcp –tcp-flags ALL NONE -j port_scan

#batasi XMAS SCAN
iptables -A INPUT -p tcp –tcp-flags ALL ALL -j port_scan
iptables -A INPUT -p tcp –tcp-flags ALL URG,PSH,FIN -j port_scan

#batasi FIN SCAN
iptables -A INPUT -p tcp –tcp-flags ACK,FIN FIN -j port_scan
iptables -A INPUT -p tcp –tcp-flags ALL FIN -j port_scan
iptables -A INPUT -p tcp –tcp-flags ALL SYN,FIN -j port_scan

#batasi ACK SCAN
iptables -A INPUT -p tcp –tcp-flags ACK,FIN FIN -j port_scan
iptables -A INPUT -p tcp –tcp-flags ACK,PSH PSH -j port_scan
iptables -A INPUT -p tcp –tcp-flags ACK,URG URG -j port_scan
```
# Pembatasan lainnya
Beberapa contoh terkait dengan pemberdayaan iptables untuk membatasi koneksi ke server sampai kepada pembahasan jumlah kokensi per-IPAddress ataupun per-IPAddress per Port<br>
1. Mengaktifkan Policy Deny pada INPUT Chain & FORWARD Chain
```
iptables --policy INPUT DROP
iptables --policy FORWARD DROP
iptables --policy OUTPUT DROP
```
2. Menerima semua permintaan dari localloop
```
iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT
```
3. Memperbolehkan semua sesi koneksi yang sudah ESTABLISHED
```
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
```
4. Hanya Menerima koneksi pada beberapa port 80, 22 dan 53
```
iptables -A INPUT -p tcp --match multiport --dports 80,22,53 -j ACCEPT
```
5. Menolak koneksi dari IP Address tertentu
```
iptables -A INPUT -s 192.168.252.12 -j DROP
```
6. Menolak koneksi dari MAC Address tertentu
```
iptables -A INPUT -m mac --mac-source 00:0F:EA:91:04:08 -j DROP
```
7. Menolak Ping pada interface tertentu
```
iptables -A INPUT -i eth1 -p icmp --icmp-type echo-request -j DROP
```
8. Menolak koneksi dari IP Address tertentu pada interface tertentu
```
iptables -A INPUT -i eth0 -s 192.168.252.12 -j DROP
```
9. Menolak lebih dari 150 koneksi ke Server
```
iptables -A INPUT -p tcp --syn -m connlimit --connlimit-above 150 -j REJECT --reject-with tcp-reset
```
10. Menolak lebih dari 15 koneksi untuk satu IP Address (ditunjukan oleh --connlimit-mask 32)
```
iptables -A INPUT -p tcp --syn -m connlimit --connlimit-above 15 --connlimit-mask 32 -j REJECT --reject-with tcp-reset
```
11. Menolak lebih dari 15 koneksi ke port 80 untuk satu IP Address (ditujukan oleh --dport 80)
```
iptables -A INPUT -p tcp --syn --dport 80 -m connlimit --connlimit-above 15 --connlimit-mask 32 -j REJECT --reject-with tcp-reset
```
12. Menolak lebih dari 15 koneksi ke port 80 untuk satu IP Address dengan pengecualian sumber koneksi dari 192.168.0.8 (ditunjukan oleh !-s 192.168.0.8)
```
iptables -A INPUT -p tcp !-s 192.168.0.8 --syn --dport 80 -m connlimit --connlimit-above 15 --connlimit-mask 32 -j REJECT --reject-with tcp-reset
```
Selain -A (add) anda dapat juga menggunakan -I (insert), jika -A menambahkan rule baru pada akhir, sedangkan -I menambahkan rule diawal daftar.
# Menangani DDos pada Apache dengan Mod-Evasive
Mod-Evasive adalah module tambahan pada Apache2 untuk mencegah serangan DDoS pada level aplikasi Web.
```
apt-get install libapache2-mod-evasive
```
Selanjutnya adalah melakukan konfigurasi mod_evasive dengan membuat file:
```
pico /etc/apache2/conf.d/mod_evasive.conf
  DOSHashTableSize    2048
  DOSPageCount        5
  DOSSiteCount        100
  DOSPageInterval     1
  DOSSiteInterval     2
  DOSBlockingPeriod   10

  DOSEmailNotify      you@yourdomain.com
  DOSLogDir           "/var/log/mod_evasive"
```
Adapun penjelasan untuk masing-masing parameter adalah sebagai berikut:<br>
1. DOSHashTableSize adalah ukuran top level node hash table yang dibutuhkan oleh mod_evasive, jika terlalu kecil, maka kinerja web menjadi rendah, disarankan untuk menggunakan ukuran yang besar untuk web yang memiliki load yang besar.<br>
2. DOSPageCount adalah jumlah pemanggilan pada halaman yang sama untuk satu satuan waktu yang ditetapkan pada DOSPageInterval, jika angka ini dilampaui, maka akan mengembalikan 403 (Forbidden), dan IP di Blacklist selama DOSBlockingPeriod.<br>
3. DOSSitePageCount adalah jumlah pemanggilan pada website untuk satu satuan waktu yang ditetapkan pada DOSSiteInterval, jika angka ini dilampaui, maka akan mengembalikan 403 (Forbidden), dan IP di Blacklist  selama DOSBlockingPeriod.<br>
4. DOSPageInterval adalah satuan waktu (detik) untuk perhitungan DOSPageCount.<br>
5. DOSSiteInterval adalah satuan waktu (detik) untuk perhitungan DOSSiteCount.<br>
6. DOSBlockingPeriod adalah satuan waktu (detik) untuk blacklist IP.<br>
dan buatlah folder untuk menampung mod_evasive
```
mkdir /var/log/mod_evasive
chown www-data /var/log/mod_evasive
```
dan aktifkan module mod_evasive
```
a2enmod mod_evasive
service apache2 restart
```
jalan program test.pl yang disediakan untuk mengetest apakah mod_evasive telah berfungsi:
```
perl /usr/share/doc/libapache2-mod-evasive/examples/test.pl
```
Maka akan tampil HTTP/1.1 403 Forbidden<br>
Lakukan instalasi software Benchmark Apache untuk melakukan pengujian
```
apt-get install apache2-utils
```
dan kita akan mensimulasikan serangan Dos untuk melihat efektivitas dari setting Mod_Evasive
```
ab -n 100 -c 10 http://localhost/index.html
tail /var/log/syslog
tail /var/log/apache2/access.log
```
dan akan tampil bahwa ip 127.0.0.1 kena blacklist pada syslog, dan 403 pada access.log
