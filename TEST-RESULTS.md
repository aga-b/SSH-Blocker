# Doğrulama sonucu

13 Eylül 2026: Python 3.12 / Windows ortamında 45 otomatik test başarılı.

```text
python -m unittest discover -s tests
Ran 45 tests
OK
```

Kontrol edilen davranışlar:

- IPv4, IPv6, OpenSSH işlem adları ve kullanıcı adına yerleştirilmiş sahte IP metinleri.
- Firewall yazma hatasında veritabanı ve journal imlecinin ilerlememesi.
- Kalıcı IP listesi, aynı dakika içinde farklı IP sayımı ve yeniden başlatma.
- Yalnızca servise ait firewall tablosunu değiştirme, eksik kuralları onarma.
- Günlük kuyruğunda kayıt kaybetmeden tekrar okuma, kaybolmuş imleçte açık hata.
- Saatlik CSV özeti, farklı eşikler, cooldown ve SMTP kesintisi sonrasında tekrar deneme.
- E-postanın alıcıların bir kısmına ulaştığı durumda yalnızca kalan alıcıları yeniden deneme.
- Başarısız SSH kaydından engel, sayaç, eşik e-postası, CSV özeti, yeniden başlatma ve elle kaldırmaya uzanan birleşik akış.

Gerçek SQLite dosyaları kullanıldı. nftables, journalctl ve SMTP bağlantıları testlerde taklit edildi; canlı sunucuya bağlanılmadı ve gerçek e-posta gönderilmedi. Config doğrulama komutu ve kurulum betiğinin shell sözdizimi de kontrol edildi. Linux/systemd, kernel firewall ve gerçek SMTP sağlayıcısıyla uçtan uca kontrol için README'deki hedef sunucu adımlarını uygulayın.
