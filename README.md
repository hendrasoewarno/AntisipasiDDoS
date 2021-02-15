# Menangani  Distributed Denial of Service (DDoS) dan Port Scanner
Pengendalian Server untuk membatasi serangan DDos adalah penting, tetapi secara umum serangan DDoS adalah sulit untuk ditangani, karena menyangkut kepada layanan dari server, terutama serangan DDoS pada layer aplikasi. Pada tulisan ini adalah membahas terkait dengan menangani Flooding pada Port, UDP dan ICMP.<br>
<br>
# Syn Flood Attack (a.k.a Half Open Attack)
Vin Cerf dan Bob Kahn merancang koneksi TCP dengan teknik Three-Way-Handshake (SYN, SYN-ACK, ACK) jauh hari sebelum ada kejahatan cyber seperti Flood. Flood merupakan salah satu modus DoS serangan cepat yang bertujuan menghabiskan sumber daya koneksi TCP pada server dengan mengekploitasi Three-Way-Handshake, sehingga tidak dapat melayani koneksi lainnya. Pada koneksi normal klien akan mengajukan permintaan koneksi dengan mengirim paket SYN ke server, kemudian server mengenali permintaan ini dan mengirim SYN-ACK kembali ke klien dan menunggu jawaban ACK dari klien. Pada Syn Flood Attack klien mengirim banyak paket SYN tetapi tidak pernah merespon SYN-ACK, sehingga koneksi pada server menjadi gantung sampai timeout, sampai pada satu level server akan kehabisan sumber daya koneksi untuk melayani koneksi sah lainnya.<br>
1. Mengaktifkan syncookies pada file /etc/sysctl.d/10-network-security.conf. Upaya untuk menangani serangan Syn flood adalah sebagai berikut:
```
net.ipv4.tcp_syncookies=1
```
2. Menggunakan iptables pembatasan
```
#batasi semua paket baru yang tidak ada SYN
iptables -A INPUT -p tcp ! --syn -m state --state NEW -j DROP

#https://www.researchgate.net/publication/265181297_Mitigating_DoSDDoS_attacks_using_iptables
#SYN FLOOD
iptables -N syn_flood
iptables -A INPUT -p tcp --syn -j syn_flood
#menggunakan module limit dengan token bucket berkapasitas awal dan maksimal 50 packet dan kemampuan pengisian kembali adalah 25 token per 1 detik
iptables -A syn_flood -m limit --limit 25/s --limit-burst 50 -j RETURN
#jika bucket full maka akan di LOG
iptables -A syn_flood -j LOG --log-prefix "SYN flood: "
#jika ingin dilanjutkan dengan drop, silakan di un-remark rule berikut ini
#iptables -A syn_flood -j DROP
#misalkan adalah serangan syn_flood 100 packet perdetik dari semua ipaddress, dan adalah 6000 packet/menit
#dengan aturan tersebut diatas, maka packet yang dapat diterima adalah 50+(25*59) = 1525 packet pada menit pertama, sisanya akan di LOG dan (DROP kalau diaktifkan)
#atau dengan kata lain:
#pada detik 1, 100 packet tiba dan langsung membuat bucket yang berkapasitas 50 full, dan sisanya 50 akan di lanjutkan ke LOG dan DROP
#pada detik 2, bucket diisi kembali dengan 25 token, dan 100 packet tiba, dan bucket penuh kembali, dan sisanya 75 alan dilanjutkan ke LOG dan DROP
#dst
    
#https://making.pusher.com/per-ip-rate-limiting-with-iptables/
#jika ingin pembatasan adalah per IP Address, maka adalah menggunakan hashlimit
#SYN FLOOD PER IP Address
iptables -N syn_flood_ipaddress
iptables -A INPUT -p tcp --syn -j syn_flood_ipaddress
#menggunakan module limit dengan token bucket berkapasitas awal dan maksimal 50 packet per ipaddress dan kemampuan pengisian kembali adalah 25 token per 1 detik
iptables -A syn_flood_ipaddress -m hashlimit --hashlimit-mode srcip --hashlimit-upto 25/sec --hashlimitburst 50 --hashlimit-name syn_flood_rate_limit -j RETURN
#jika bucket full maka akan di LOG
iptables -A syn_flood_ipaddress -j LOG --log-prefix "SYN flood: "
#jika ingin dilanjutkan dengan drop, silakan di un-remark rule berikut ini
#iptables -A syn_flood_ipaddress -j DROP
#misalkan adalah serangan syn_flood 100 packet perdetik dari satu ipaddress, dan adalah 6000 packet/menit
#dengan aturan tersebut diatas, maka packet yang dapat diterima adalah 50+(25*59) = 1525 packet pada menit pertama , sisanya akan di LOG dan (DROP kalau diaktifkan)
#atau dengan kata lain:
#pada detik 1, 100 packet tiba dan langsung membuat bucket yang berkapasitas 50 full, dan sisanya 50 akan di lanjutkan ke LOG dan DROP
#pada detik 2, bucket diisi kembali dengan 25 token, dan 100 packet tiba, dan bucket penuh kembali, dan sisanya 75 alan dilanjutkan ke LOG dan DROP
#dst

#https://kb.mazebolt.com/knowledgebase/urg-syn-flood/
iptables -A INPUT -p tcp --tcp-flags URG,SYN URG,SYN -j LOG --log-prefix "URG-SYN flood: "
iptables -A INPUT -p tcp --tcp-flags URG,SYN URG,SYN -j DROP

#https://kb.mazebolt.com/knowledgebase/urg-psh-syn-flood/
iptables -A INPUT -p tcp --tcp-flags URG,PSH,SYN URG,PSH,SYN -j LOG --log-prefix "URG-PSH-SYN flood: "
iptables -A INPUT -p tcp --tcp-flags URG,PSH,SYN URG,PSH,SYN -j DROP

#UDP FLOOD
iptables -N udp_flood
iptables -A INPUT -p udp ! --dport 53 -j udp_flood  
iptables -A udp_flood -m state --state NEW –m recent --update --seconds 1 --hitcount 10 -j RETURN  
iptables -A syn_flood -j LOG --log-prefix "UDP flood: "
iptables -A udp_flood -j DROP
#membatasi maksimal 10 koneksi UDP baru per detik, kecuali layanan DNS

#ICMP FLOOD/Smurf Attack
iptables -N icmp_flood  
iptables -A INPUT -p icmp -j icmp_flood
#menggunakan module limit dengan token bucket berkapasitas maksimal 3 packet dan kemampuan pengisian kembali adalah 1 token per 1 detik
iptables -A icmp_flood -m limit --limit 1/s --limit-burst 3 -j RETURN
#jika diatas 3 packet akan di LOG dan di DROP
iptables -A syn_flood -j LOG --log-prefix "ICMP flood: "
iptables -A icmp_flood -j DROP
#misalkan adalah serangan icmp_flood 100 packet perdetik, dan adalah 6000 packet/menit
#dengan aturan tersebut diatas, maka packet yang dapat diterima adalah 3+59 = 62 packet/menit, sisanya akan di LOG dan DROP

#OR BLOCK ALL ICMP
#iptables -A INPUT -p icmp -j DROP
```
Fungsi dari perintah iptables -N adalah membuat suatu chain baru, sehingga lebih mudah dimaintain seperti iptables -L syn_flood, maupun iptables -F syn_flood, dan kemudian hasil log dapat dilihat pada /var/log/kern.log.
# TCP Port Scanner
Port Scanner merupakan aktvitas untuk mendapatkan informasi terkait dengan Open Port, Closed Port, dan Filtered Port. Menurut RFC 793, untuk TCP segment yang tidak memiliki SYN, ACK, RST, maka server akan merespon RST jika Port adalah Close, dan tidak memberikan respon kalau Port adalah Open. Null Scan, FIN Scan dan XMas Scan melakukan eksploitasi terhadap prilaku ini. Pada NULL scan tidak ada flag yang diset, pada FIN Scan hanya flag FIN yang diset, pada XMas Scan melakukan set terhadap flag URG, PSH, dan FIN. Nill Scan, FIN Scan dan XMAs Scan menggunakan bandwith yang kecil bagi penyerang dan tidak di LOG oleh Sistem Operasi target, tetapi dapat dikenali dengan menggunakan system IDS maupun Firewall. Dengan eksploitasi terhadap RFC 793 respon hanya terkait dengan Port adalah Open atau Close, tetapi bagaimana dengan Filter? disinilah ACK Scan digunakan untuk mengidentifikasi apakah port yang open tersebut dalam keadaan Filtered atau Un-Filtered(keberadaan Firewall), jika ACK Scan dikirim ke server dan tidak ada balasan atau ICMP destination UNREACHABLE maka ada firewall yang menfilter trafik anda, dan sebaliknya server akan mengembalikan RST<br>
```
#batasi fragment package
iptables -A INPUT -f -j DROP

#membuat LOG SCAN DROP 
iptables -N port_scan
iptables -A port_scan -j LOG --log-prefix "Port Scanner: "
#DROP akan dilihat sebagai Filtered pada nmap (DENY -> close)
iptables -A port_scan -j DROP

#batasi semua NULL SCAN
iptables -A INPUT -p tcp --tcp-flags ALL NONE -j port_scan

#batasi XMAS SCAN
iptables -A INPUT -p tcp --tcp-flags ALL ALL -j port_scan
iptables -A INPUT -p tcp --tcp-flags ALL URG,PSH,FIN -j port_scan

#batasi FIN SCAN
iptables -A INPUT -p tcp --tcp-flags ACK,FIN FIN -j port_scan
iptables -A INPUT -p tcp --tcp-flags ALL FIN -j port_scan
iptables -A INPUT -p tcp --tcp-flags ALL SYN,FIN -j port_scan

#batasi ACK SCAN
iptables -A INPUT -p tcp --tcp-flags ACK,PSH PSH -j port_scan
iptables -A INPUT -p tcp --tcp-flags ACK,URG URG -j port_scan
```
Bagaimana dengan NMAP scan? NMap menggunakan pendekatan yang halus, yaitu mengakhiri koneksi dengan RST (SYN, SYN=-ACK, RST), sehingga koneksi tidak direkam oleh system operasi target.
Bagaimana dengan Server Windows? Server Windows akan merespon NULL Scan, FIN Scan dan XMas Scan senantiasa dengan RST, sehingga scanner akan melaporkan Port adalah Close.
# UDP Port Scanner
Pada server normalnya layanan UDP adalah terkait dengan DNS dan DHCP, tetapi pada umumnya Pentester melakukan Scan UDP untuk mendapatkan kemungkinan server ada Port UDP yang terbuka karena terinfeksi Malware ataupun Spyware. Jika UDP Scan mendapatkan response ICMP destination UNREACHABLE, maka port adalah Close.

# Pembatasan lainnya
Beberapa contoh terkait dengan pemberdayaan iptables untuk membatasi koneksi ke server sampai kepada pembahasan jumlah koneksi per-IPAddress ataupun per-IPAddress per Port<br>
1. Mengaktifkan Policy Deny pada INPUT Chain & FORWARD Chain
```
iptables --policy INPUT DROP
iptables --policy FORWARD DROP
iptables --policy OUTPUT ACCEPT
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
4. Hanya Menerima koneksi pada beberapa port 25 (SMTP Relay), 443 (HTTPS), 587 (SMTP TLS), 995 (POPS TLS)
```
iptables -A INPUT -p tcp --match multiport --dports 25, 443, 587, 995 -j ACCEPT
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
10. Menolak lebih dari 35 koneksi dari IP Address kelas C (ditunjukan oleh --connlimit-mask 192.0.0.0/24 )
```
iptables -A INPUT -p tcp --syn -m connlimit --connlimit-above 35 --connlimit-mask 192.0.0.0/24 -j REJECT --reject-with tcp-reset
```
10. Menolak lebih dari 15 koneksi untuk satu IP Address (ditunjukan oleh --connlimit-mask 32)
```
iptables -A INPUT -p tcp --syn -m connlimit --connlimit-above 15 --connlimit-mask 32 -j REJECT --reject-with tcp-reset
```
11. Menolak lebih dari 15 koneksi ke port 443 untuk satu IP Address (ditujukan oleh --dport 80)
```
iptables -A INPUT -p tcp --syn --dport 443 -m connlimit --connlimit-above 15 --connlimit-mask 32 -j REJECT --reject-with tcp-reset
```
12. Menolak lebih dari 15 koneksi ke port 443 untuk satu IP Address dengan pengecualian sumber koneksi dari 192.168.0.8 (ditunjukan oleh !-s 192.168.0.8)
```
iptables -A INPUT -p tcp !-s 192.168.0.8 --syn --dport 443 -m connlimit --connlimit-above 15 --connlimit-mask 32 -j REJECT --reject-with tcp-reset
```
13. Menolak empty package ke port 443
```
iptables -I INPUT -p tcp --dport 443 -m length --length 20 -j DROP
iptables -I INPUT -p tcp --dport 443 -m length --length 32 -j DROP
```
14. Menolak lebih dari 2 koneksi ke port 587, 995 untuk satu IP Address dari interface eth0 (internet)
```
iptables -A INPUT -i eth0 -p tcp --syn --match multiport --dports 587, 995 -m connlimit --connlimit-above 2 --connlimit-mask 32 -j REJECT --reject-with tcp-reset
```
15. Menolak lebih dari 5 koneksi SSH per menit per srcip
```
iptables -A INPUT -p tcp --dport 22 -m state --state NEW -m hashlimit --hashlimit-name SSH --hashlimit-above 5/min --hashlimit-mode srcip -j REJECT
```
16. Melakukan log dan block terhadap upaya serangan heartbleep:
```
# Log rules
iptables -t filter -A INPUT -p tcp --dport 443 -m u32 --u32 "52=0x18030000:0x1803FFFF" -j LOG --log-prefix "BLOCKED: HEARTBEAT"
# Block rules
iptables -t filter -A INPUT -p tcp --dport 443 -m u32 --u32 "52=0x18030000:0x1803FFFF" -j DROP
```
Selain -A (add) anda dapat juga menggunakan -I (insert), jika -A menambahkan rule baru pada akhir, sedangkan -I menambahkan rule diawal daftar.
kemudian untuk menampilkan daftar rule aktif pada firewall:
```
iptables -L --line-number
iptabkes -L INPUT --line-number
```
dan untuk menghapus rule tertentu berdasarkan nomor baris 1
```
iptables -D INPUT 1
```
# ip_conntrack: table full, dropping packet
Jika anda mengalami pesan ip_conntrack: table full, dropping packet setelah melakukan setting tersebut diatas, maka berarti perlu memeriksa keberadaan setting nilai ip_contract
```
cat /proc/sys/net/ipv4/ip_conntrack_max
atau
cat /proc/sys/net/ipv4/netfilter/ip_conntrack_max
```
Kemudian lakukan perubahan nilai setting
```
echo 655361  > /proc/sys/net/ipv4/ip_conntrack_max
atau
echo 655361  > /proc/sys/net/ipv4/netfilter/ip_conntrack_max
```
# Kombinasi ipset dan iptables
```
apt-get install ipset
ipset -N black_list iphash
ipset -A black_list 1.1.1.1
ipset -A black_list 2.2.2.2
iptables -A INPUT -m set --set black_list src -j DROP
```
adalah setara dengan
```
iptables -A INPUT -s 1.1.1.1 -j DROP
iptables -A INPUT -s 2.2.2.2 -j DROP
```
Jika ingin hapus ipaddress tertentu dari ipset
```
ipset -D blacklist 1.1.1.1
```
jika muncul pesan module ip_set not found, maka dapat diartikan bahwa kernel anda tidak mendukung module ip_set, sehingga anda perlu mengkompilasi kernel dengan mengaktifkan module ip_set.
# Kompilasi ulang kernel Linux
Dalam hal ini penulis menggunakan ubuntu 9.04 dengan kernel-2.6.26 yang tidak mendukung module ipset, untuk itu kita perlu mendownload kernel.2.6.39.4.
```
apt-get install kernel-package libncurses5-dev fakeroot wget bzip2
cd /usr/src
wget https://launchpad.net/linux/2.6.39/2.6.39.4/+download/linux-2.6.39.4.tar.gz
tar xvf linux-2.6.39.4.tar.gz
ln -s linux-2.6.39.4.tar.gz linux
cd linux
#duplikasi konfigurasi dari kernel saat ini
cp /boot/config-`uname -r` ./.config
make menuconfig

#aktifkan setting ipset
[*] Networking support  --->
    Networking options  --->
    [*] Network packet filtering framework (Netfilter) --->
        <M>  IP set support --->

as well as
             Core Netfilter Configuration --->       
                <M>  set target and match support
make clean
make
make modules
make firmware
make modules_install
make firmware_install
make install
#membuat initramfs
cd /boot
sudo mkinitramfs -ko initrd.img-2.6.39.4 2.6.39.4
#update grub
update-grub
```
# Banned alamat IP yang melakukan scan
Misalkan server kita tidak membuka layanan Telnet(23), tetapi ada client yang mencoba meminta koneksi ke port 23, sehingga dinyakini bahwa client adalah mencoba melakukan scan terhadap server, sehingga segera dimasukan ke data alamat yang di banned.
```
ipset -N banned_list iphash
iptables -A INPUT -p tcp --dport 23 -j SET --add-set banned_list src
iptables -A INPUT -m set --set banned_list src -j DROP
```
# Kesimpulan
Upaya menghadapi DoS pada level firewall adalah menggunakan strategy membatasi jumlah koneksi ke Port tertentu per Ip Address. Pendekatan yang lain adalah dengan menyediakan suatu bucket token yang memiliki kapasitas terbatas dan token yang terpakai akan dipulihkan kembali dengan laju sejumlah token tertentu per-satuan waktu, jika token yang tersedia habis maka permintaan koneksi akan ditolak sampai kapasitas yang memadai tersedia kembali.
