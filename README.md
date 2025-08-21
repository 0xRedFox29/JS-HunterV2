🕵️‍♂️ JS Hunter V2 

JS Hunter V2 adalah alat untuk melakukan JavaScript reconnaissance pada domain target, dengan fitur:

Crawling halaman HTML untuk menemukan file inline & external JavaScript

Multi-threaded scanning → lebih cepat dalam fetch dan analisis

Subdomain enumeration otomatis via crt.sh
 (tanpa perlu install subfinder/amass)

Sensitive data detection → mencari API Keys, Token, Credential, Email, Private Key, dsb.

Output JSON report → mudah dipakai untuk dokumentasi bug bounty

⚡ Cara Pakai
Buat folder dengan nama bebas di Folder Manager (misalnya: GAU V2)
Buka folder pada VS Code
Buat file baru dengan nama js_hunter_mt.py
Copy dan Paste kode program python di Repo ini
Jalankan dengan perintah
Scan domain langsung:
```bash
python3 js-hunterV2.py target.com
```
Scan + subdomain (pakai crt.sh):
```bash
python3 js-hunterV2.py target.com --subs --threads 16
```
Redudant dua kali
```bash
python3 js-hunterV2.py target.com --subs --threads 16 --threads 8
```
📂 Output

Output otomatis disimpan dalam file JSON:

target.id_report.json

Struktur output:

{
  "generated_utc": "2025-08-20 14:05:14",
  "stats": {
    "targets": 7,
    "external_js": 116,
    "inline_scripts": 5195,
    "sensitive_items_groups": 103
  },
  "results": [
    {
      "target": "https://target.id",
      "external_js": [...],
      "inline_scripts": [...],
      "sensitive_items_groups": {...},
      "findings": [...]
    }
  ]
}

🔍 Fitur Utama

Subdomain Enumeration (--subs)

Menggunakan API crt.sh untuk menemukan subdomain publik.

Berguna untuk memperluas permukaan serangan (attack surface).

Multi-threaded Crawling (--threads)

Menggunakan ThreadPoolExecutor untuk mempercepat fetching JS file.

Default = 10 threads, bisa diatur.

Sensitive Data Finder

Regex untuk mendeteksi:

Google API Key (AIza...)

Firebase URL

AWS Access Key

Secret Key

Authorization Bearer Token

Basic Auth credential

Email address

Private Key

Crawling Depth

Otomatis mengekstrak semua <script> dari halaman target.

Inline script ditampilkan sebagai potongan (preview).

External JS di-fetch ulang untuk dianalisis.

Report JSON

Statistik jumlah target, JS file, script inline.

Grup temuan sensitif berdasarkan kategori.

Mudah dipakai untuk laporan bug bounty (bisa dikonversi ke HTML/Markdown).

📑 Contoh Hasil Scan

Dari file Hasil Scanning.txt, scanning alkademi.id menghasilkan:

Target total: 7 subdomain valid (target.id, *.target.id, dll.)

External JS ditemukan: 116 file

Inline script: 5195 script

Sensitive items group: 103 temuan

Beberapa inline script menunjukkan sensitive found → indikasi adanya data penting (API keys/token) di dalam JavaScript.
