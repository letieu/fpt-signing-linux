# FPT CA USB Signing Service & CLI for Linux (Arch Linux)

Phiên bản độc lập (Headless) trích xuất từ **FPT USB Signing Tool**, chạy trực tiếp trên **Arch Linux** (hoặc bất kỳ Linux distro nào) mà không cần Electron UI hay máy ảo Windows.

---

## 🎯 Tính năng

1. **Giao Diện Web Ký PDF (Web UI)**: Truy cập trực tiếp `http://127.0.0.1:35317` để kéo-thả ký file PDF, hỗ trợ nhúng chữ ký số chuẩn PAdES (hiển thị tích xanh trong Adobe Acrobat) và dấu ký số trực quan (Visual Stamp).
2. **Web Browser Signing Daemon**: Chạy Express server trên `http://127.0.0.1:35317` hỗ trợ đầy đủ các cổng thuế / hóa đơn điện tử FPT e-Invoice (Chrome, Firefox, Brave trên Linux).
3. **CLI Direct Signing**: Ký trực tiếp file PDF / XML từ dòng lệnh (`node cli-sign.js document.pdf`).
4. **Auto PIN login**: Tự động xác thực mã PIN qua PKCS#11 mà không cần bấm thủ công.
5. **Hỗ trợ phần cứng gốc**: Token Feitian ePass2003 được hỗ trợ gốc (native CCID) thông qua OpenSC driver `epass2003`.
---

## 📦 1. Cài đặt các gói trên Arch Linux

Chạy lệnh pacman để cài đặt CCID driver, smartcard daemon và OpenSC:

```bash
sudo pacman -S pcsclite ccid opensc nodejs npm
```

Kích hoạt và khởi chạy dịch vụ đọc thẻ thông minh `pcscd`:

```bash
sudo systemctl enable --now pcscd
```

---

## 🔍 2. Kiểm tra nhận diện Token

Cắm USB Token FPT vào máy Arch Linux và kiểm tra:

```bash
# 1. Kiểm tra PC/SC reader đã nhận Feitian ePass2003 chưa:
opensc-tool -l

# 2. Liệt kê thông tin PKCS#11 module:
pkcs11-tool --module /usr/lib/opensc-pkcs11.so -L

# 3. Liệt kê chứng thư số trên token (nhập PIN của bạn khi được hỏi):
pkcs11-tool --module /usr/lib/opensc-pkcs11.so --login --pin YOUR_PIN -O
```

> **Lưu ý**: Nếu bạn thấy `Feitian ePass2003` và Certificate công ty của bạn, USB Token đã sẵn sàng 100%!

---

## 🚀 3. Cài đặt và Chạy Signing Server

1. Sao chép thư mục `fpt-signing-linux` vào máy Arch Linux (ví dụ: `~/.local/share/fpt-signing-linux` hoặc `~/fpt-signing-linux`).
2. Cài đặt các thư viện Node.js:

```bash
cd fpt-signing-linux
npm install
```

3. Khởi chạy server:

```bash
node server.js
```

Khi chạy thành công, console sẽ hiển thị:
```text
[PKCS#11] Loading module: /usr/lib/opensc-pkcs11.so
[PKCS#11] Found Token: Feitian ePass2003
[PKCS#11] Loaded Cert: CONG TY ABC (Serial: 54010104399688a3f58291e8d2381115)
======================================================
🚀 FPT USB Signing Service is listening on 127.0.0.1:35317
📡 Ready to receive signing requests from web browser portals!
======================================================
```

Bây giờ bạn có thể mở trình duyệt trên Arch Linux vào portal hóa đơn điện tử FPT để ký hóa đơn bình thường!

---

## ⚙️ 4. Chạy ngầm tự động cùng hệ thống (Systemd User Service)

Để server tự động chạy nền mỗi khi đăng nhập Arch Linux mà không cần mở terminal:

```bash
# 1. Tạo thư mục systemd user (nếu chưa có):
mkdir -p ~/.config/systemd/user

# 2. Copy file service:
cp fpt-signing.service ~/.config/systemd/user/

# 3. Kích hoạt và khởi động:
systemctl --user daemon-reload
systemctl --user enable --now fpt-signing

# 4. Kiểm tra trạng thái:
systemctl --user status fpt-signing
```

---

## ✍️ 5. Sử dụng CLI ký trực tiếp từ dòng lệnh

Bạn có thể ký nhanh tài liệu mà không cần thông qua giao diện web:

```bash
# Ký PDF (tạo chữ ký số PKCS#7 detached):
node cli-sign.js hop_dong.pdf

# Ký XML (chuẩn chữ ký số XMLDSig):
node cli-sign.js hoa_don.xml

# Tùy biến mã PIN và đường dẫn file xuất:
node cli-sign.js invoice.xml --pin 12345678 --out hoa_don_da_ky.xml
```

---

## 🔒 6. Cấu hình PIN và Thư viện PKCS#11 (`config.json`)

Sao chép từ file mẫu:
```bash
cp config.example.json config.json
```

Chỉnh sửa `config.json`:
```json
{
  "port": 35317,
  "pin": "12345678",
  "pkcs11Path": "/usr/lib/opensc-pkcs11.so"
}
```
Hoặc bạn có thể truyền biến môi trường:
```bash
export TOKEN_PIN="12345678"
node server.js
```
