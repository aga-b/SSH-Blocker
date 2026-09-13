# SSH Guard

Ubuntu 22.04+ / Debian 12+ üzerinde, SSH için ilk yanlış parola kaydında kaynak IP'yi kalıcı engelleyen systemd servisi. Python 3.10+ standart kütüphanesini, journald, nftables ve SQLite kullanır; ek Python paketi gerektirmez.

- IPv4 ve IPv6 adresleri desteklenir. Engellenenler kalıcı veritabanında tutulur; elle kaldırılana kadar engelli kalır.
- Varsayılan `block_scope: "all"`, kaynak IP'den **bu sunucuya gelen bütün port ve protokolleri** engeller. `"ssh"` seçeneği yalnızca `ssh_ports` içindeki TCP portlarını engeller. Yönlendirilen/container trafiği için FORWARD kuralı kurmaz.
- Her UTC takvim dakikasındaki yeni engellenen **farklı IP sayısı** saklanır. Bu metrik bağlantı veya başarısız deneme sayısı değildir; zaten engelli bir IP'nin tekrarları artış yaratmaz. Aynı dakika içinde elle kaldırılıp tekrar engellenen IP de o dakika bir kez sayılır.
- Engellenen IP'ler varsayılan olarak saatte bir e-posta özetiyle bildirilir. Dakikalık sayı 10, 50 veya 100 eşiğine ulaşınca aynı alıcılara ayrıca uyarı gönderilir. Aralıklar ve eşikler config üzerinden değişir.
- E-posta kuyruğu diskte tutulur; SMTP kesintisi IP engellemeyi durdurmaz. Başarısız alıcılar yeniden denenir.

## Kurulum

Bu klasörü sunucuya aktarın. Kurulum komutları **hedef Ubuntu/Debian sunucusunda** çalıştırılır:

```sh
sudo apt-get update
sudo apt-get install python3 nftables systemd openssh-server ca-certificates
sudo sh ./install.sh
```

Kurucu dosyaları yerleştirir ve systemd tanımını yeniler; servisi başlatmaz veya açılışta çalışacak şekilde etkinleştirmez. Mevcut config ve SMTP parola dosyası korunur. Paket kurulumu çalışan bir SSH Guard servisi saptarsa durur; güncellemeden önce servisi durdurun.

```sh
sudo nano /etc/ssh-guard/config.conf
sudo nano /etc/ssh-guard/smtp.env
```

Önce `allowlist` dizisine **yönetim bağlantınızın sunucudan görünen gerçek IP'sini veya güvenilir CIDR aralığını** ekleyin. Varsayılan liste yalnızca loopback adreslerini içerir. Aynı NAT çıkış IP'sini paylaşan kullanıcıların tümü bir IP engelinden etkilenir. Sonra gerçek SMTP sunucunuzu, göndericiyi ve alıcıları yazın; örnek `example.com` değerleriyle servis başlatılmaz.

`/etc/ssh-guard/smtp.env` dosyasına parolayı yazın:

```text
SSH_GUARD_SMTP_PASSWORD='SMTP_PAROLANIZ'
```

Bu dosya systemd `EnvironmentFile` biçimindedir; shell betiği olarak çalıştırılmaz. Parolayı config içine veya komut satırına yazmayın. Dosyalar kurulumda root kullanıcısına ait ve yalnızca root tarafından okunabilir olur.

```sh
sudo ssh-guard validate
sudo systemctl enable --now ssh-guard
sudo systemctl status ssh-guard --no-pager
sudo journalctl -u ssh-guard -n 100 --no-pager
```

`validate` config yapısını doğrular; SMTP bağlantısını, parolayı, journal erişimini veya firewall yetkisini test etmez. Servis çalışırken gerçek ortama ilişkin kontroller yapılır. Başlatma sonrasında servis durumunu ve günlükteki hataları kontrol edin.

## Yapılandırma

`config.conf` dosyası **JSON** biçimindedir: yorum satırı ve son elemandan sonra virgül desteklenmez. Tüm alanlar örnek dosyada bulunur. Değişikliklerden sonra:

```sh
sudo ssh-guard validate
sudo systemctl restart ssh-guard
```

| Alan | Varsayılan | Anlamı |
| --- | --- | --- |
| `allowlist` | `127.0.0.0/8`, `::1/128` | Engellenmeyecek IP/CIDR adresleri; yönetim IP'nizi ekleyin. |
| `block_scope` | `"all"` | Bütün gelen trafik; sadece SSH için `"ssh"`. |
| `ssh_ports` | `[22]` | `block_scope: "ssh"` olduğunda engellenecek TCP portları. |
| `journal_units` | `ssh.service`, `sshd.service` | SSH günlüklerinin güvenilir systemd birimleri. |
| `notifications.digest_interval_seconds` | `3600` | E-posta özeti aralığı; 30 dakika için `1800`. |
| `notifications.thresholds` | `[10, 50, 100]` | Dakikada yeni engellenen IP sayısı için artan, benzersiz eşikler. `[]` eşik uyarılarını kapatır. |
| `notifications.threshold_cooldown_seconds` | `300` | Aynı eşik için tekrarlanan uyarılar arasındaki asgari süre. |
| `notifications.retry_seconds` | `60` | İlk tekrar denemesinin bekleme süresi; her başarısızlıkta iki katına çıkar, en fazla 3600 saniye. |
| `notifications.poll_seconds` | `2` | Bildirim işçisinin kontrol aralığı. |
| `notifications.send_empty_digest` | `false` | Yeni engelleme yoksa özet gönderilmez. |
| `smtp.recipients` | örnek adres | Hem özet hem eşik uyarısı alan e-posta adresleri. |
| `smtp.enabled` | `true` | `false` e-posta gönderimini kapatır; IP engelleme sürer. |
| `smtp.mode` / `smtp.port` | `"starttls"` / `587` | Şifreli SMTP; doğrudan TLS için `"ssl"`, sağlayıcınızın portuyla. |
| `smtp.username` | örnek adres | SMTP giriş adı; kimlik doğrulamasız güvenilir relay için boş metin. |
| `smtp.password_env` | `SSH_GUARD_SMTP_PASSWORD` | Parolanın okunacağı ortam değişkeni. |
| `smtp.timeout_seconds` | `15` | SMTP ağ işlemi zaman aşımı. |
| `smtp.subject_prefix` | `SSH Guard` | E-posta konu başlığı öneki. |
| `reconcile_seconds` | `30` | Veritabanı ile servis firewall tablosunu karşılaştırma ve onarma aralığı. |
| `firewall_table` | `ssh_guard` | Servisin yönettiği özel `inet` nftables tablosu. |
| `database` | `/var/lib/ssh-guard/state.sqlite3` | IP listesi, dakika kayıtları ve bildirim kuyruğu. |

`smtp.host` ve `smtp.from_addr` da sağlayıcınıza göre ayarlanmalıdır. SMTP sertifikaları sistem güven deposuyla doğrulanır; düz metin SMTP seçeneği yoktur. Servis birimi yalnızca `/var/lib/ssh-guard` altında kalıcı yazmaya izin verir; `database` yolunu bu dizin altında tutun. Firewall tablo adını değiştirirken eski tablo kendiliğinden silinmez; eski servis tablosunu bakım sırasında açıkça kaldırın.

Özet, başlangıçtan veya önceki özetten itibaren belirtilen süre dolduğunda hazırlanır; bütün yeni engelleme kayıtları CSV ekindedir. Kesinti sonrasında henüz özete alınmamış kayıtlar bir sonraki özette birlikte yer alır. Eşik uyarıları saatlik özeti beklemez: bir kontrol anında birkaç eşik birden aşılmışsa uygun en yüksek eşik için bir e-posta hazırlanır. Daha yüksek bir eşiğe sonradan ulaşılması yeni uyarı oluşturabilir. Aynı dakika/eşik için en fazla bir uyarı oluşturulur; cooldown sırasında bastırılan eşikler sonradan ayrıca gönderilmez.

SMTP kapatıldığında bildirim imleçleri ilerlemez; tekrar açılınca biriken kayıtlar işlenir. Kuyruğa alınmış e-postalar oluşturuldukları andaki alıcı listesini korur; config değişikliği yeni e-postalara uygulanır. SMTP sunucusunun kabul ettiği alıcıya normal yeniden denemede tekrar gönderilmez. Ancak sunucu kabulü ile veritabanına kaydetme arasında süreç çökerse aynı e-posta tekrar gidebilir; SMTP tam bir kez teslim garantisi vermez.

## Liste, dakika oranı ve engel kaldırma

```sh
# Aktif engeller
sudo ssh-guard list

# Kaldırılmış engeller dahil kayıtlar; makine tarafından okunabilir çıktı
sudo ssh-guard list --all --json

# Son 60 UTC dakikasındaki yeni engellemeler
sudo ssh-guard rates --minutes 60
sudo ssh-guard rates --minutes 60 --json

# Tek IP'yi hem veritabanından hem firewall engelinden çıkarma
sudo ssh-guard unban 203.0.113.7

# Servis ve gerçek firewall durumu
sudo journalctl -u ssh-guard -f
sudo nft list table inet ssh_guard
```

`203.0.113.7` dokümantasyon için örnek adrestir; komutta gerçek IP'yi kullanın. Kalıcı izin vermek istiyorsanız IP/CIDR'yi `allowlist` içine de ekleyin. Elle kaldırılan IP sonraki yanlış parola girişinde yeniden engellenebilir. Başka config kullanımı: `sudo ssh-guard --config /etc/ssh-guard/config.conf list`.

## Kalıcılık ve çalışma sınırları

İlk başlangıç yeni SSH günlüklerinden başlar; eski başarısız girişleri topluca engellemez. Sonraki başlangıçlarda saklanan journal imlecinden devam eder. Kaydedilen imleç journal temizliği veya yeniden başlatmada kaybolmuşsa servis sessizce olay atlamak yerine hata verir. Journal saklama süresini sunucunun kesinti süresine uygun tutun ve kalıcı journald depolaması kullanın. `journalctl` imleç ve takip seçenekleri için [Debian journalctl belgesi](https://manpages.debian.org/bookworm/systemd/journalctl.1.en.html).

Journal imleci kaybolduysa mevcut engeller geri yüklenir fakat yeni olay takibi başlayamaz. Günlük saklama ayarını düzelttikten sonra, servisi durdurarak açık bir başlangıç zamanı seçin:

```sh
sudo systemctl stop ssh-guard
sudo ssh-guard reset-cursor --since 2026-09-13T10:00:00+03:00
sudo systemctl reset-failed ssh-guard
sudo systemctl start ssh-guard
```

Örnek zamanı kendi olayınıza göre değiştirin. `--since now` yalnızca şu andan itibaren devam eder. Seçilen zamandan önceki olaylar atlanır; silinmiş günlükler kurtarılamaz. Eski bir zaman seçerseniz o zamandan beri elle kaldırılmış IP'ler eski başarısız girişlerinden dolayı yeniden engellenebilir. Bu komut engel listesini ve sayaç geçmişini silmez; çalışan servis varken uygulanmaz.

`systemctl stop ssh-guard` mevcut firewall kurallarını kaldırmaz. Yeniden başlatmada aktif IP listesi SQLite'tan yüklenir; makine açılışında kalıcılık için servis etkinleştirilmiş olmalıdır. Makine açılırken servis başlayana kadarki sürede bu kurallar henüz kurulmamış olabilir. Başka bir firewall yöneticisi tabloyu silerse servis normalde `reconcile_seconds` içinde onarır; aradaki süre korumasız olabilir. Servis yalnızca kendi sahiplik işaretini taşıyan tabloyu yönetir, aynı adlı başka tabloyu değiştirmeyi reddeder.

Yalnızca güvenilir SSH biriminden ve `sshd`/`sshd-session`/`sshd-auth` işleminden gelen OpenSSH `Failed password` kayıtları işlenir. OpenSSH 10'daki işlem ayrımı [resmî sürüm notlarında](https://www.openssh.org/releasenotes.html) açıklanır. `logger` ile yazılan taklit kayıtlar, public-key hataları ve farklı biçimli PAM/keyboard-interactive mesajları tetiklemez. SSH başka bir systemd biriminde çalışıyorsa `journal_units` ayarını gerçek birim adına göre değiştirin. Journald'a hiç ulaşmayan veya günlük hız sınırıyla atılan olaylar algılanamaz. Engelleme, yanlış parola olayının günlüğe ulaşmasından sonra uygulanır.

Veritabanı kayıtları otomatik silinmez; uzun dönem kullanımda disk alanını izleyin. Veritabanını yedeklemek için SQLite backup yöntemini kullanın veya servisi durdurup veritabanını WAL yan dosyalarıyla birlikte yedekleyin. Etkin SQLite dosyasını tek başına kopyalamayın.

## Acil erişim ve devre dışı bırakma

Yanlışlıkla kendi IP'nizi engellerseniz sunucu konsolundan ya da allowlist içindeki başka bir bağlantıdan `ssh-guard unban IP` kullanın. Tüm SSH Guard engellerini geçici kaldırmak için önce servisi durdurun, sonra **yalnızca bu servisin tablosunu** silin:

```sh
sudo systemctl stop ssh-guard
sudo nft delete table inet ssh_guard
```

`firewall_table` değiştiyse o adı kullanın. Veritabanı korunduğu için servis yeniden başlatılınca aktif engeller geri gelir. Otomatik başlatmayı kapatmak için `sudo systemctl disable ssh-guard` kullanın. Ana nftables kurallarını topluca temizlemeyin.

## Doğrulama

Yerel testleri paket klasöründe çalıştırabilirsiniz:

```sh
python3 -m unittest discover -s tests -v
```

Bu paket Windows çalışma ortamında hazırlanmıştır; gerçek Linux firewall, systemd ve SMTP uçtan uca doğrulaması hedef sunucuda ayrıca yapılmalıdır. Hedefte ikinci bir test IP'sinden yanlış SSH parolası girerek IP'nin listede ve nftables setinde belirdiğini, dakika sayısının bir arttığını kontrol edin. Test IP'si allowlist'te olmamalı; yönetim bağlantınızı bunun için kullanmayın. E-posta testi için aralığı geçici olarak `60`, eşikleri `[1]` yapıp gerçek test IP'sinin bildirimini kontrol edin; ardından istediğiniz değerlere dönün. `unban` ve servis yeniden başlatma sonrası kalıcılığı da doğrulayın.

Servis biriminin dosya erişimi ve yetki sınırları [systemd.exec belgesine](https://manpages.debian.org/bookworm/systemd/systemd.exec.5.en.html), IP engelleme kuralları [nftables komut belgesine](https://netfilter.org/projects/nftables/manpage.html) dayanır.
