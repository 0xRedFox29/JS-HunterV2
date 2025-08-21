JS-Hunter V2 Scanner

Buat folder dengan nama bebas di Folder Manager (misalnya: GAU V2)
Buka folder pada VS Code
Buat file baru dengan nama js_hunter_mt.py
Copy dan Paste kode program python di Repo ini
Jalankan dengan perintah
Scan domain langsung:
```bash
python3 js-hunterV2.py alkademi.id
```
Scan + subdomain (pakai crt.sh):
```bash
python3 js-hunterV2.py alkademi.id --subs --threads 16
```
Redudant dua kali
```bash
python3 js-hunterV2.py alkademi.id --subs --threads 16 --threads 8
```
