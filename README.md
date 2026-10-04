# wordpress-telegram-guvenlik-eklentisi
2. adımlı 2 FA oturum açma ekranı

## Kullanım

`telegram-2fa-login.php` dosyasını `wp-content/plugins/` altına kopyalayıp etkinleştirin. Bot Token ve Chat ID'yi **Ayarlar > Telegram 2FA** sayfasından (genel) veya kullanıcı profilinden (kişisel) girin. Şifre doğrulandıktan sonra Telegram'a 10 haneli, 5 dakika geçerli, tek kullanımlık kod gönderilir; 5 hatalı denemede kod iptal edilir. Kod gönderilemezse giriş engellenir.
