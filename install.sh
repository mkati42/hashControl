#!/bin/bash
# Kurulum scripti: Gereksinimleri yükler ve uygulamayı başlatır
set -e

if ! command -v python3 &> /dev/null; then
    echo "Python3 yüklü değil!"
    exit 1
fi

if ! command -v pip3 &> /dev/null; then
    echo "pip3 yüklü değil!"
    exit 1
fi

pip3 install -r requirements.txt

if [ ! -f banner.png ]; then
    echo "UYARI: banner.png dosyasını proje klasörüne ekleyin!"
fi

echo "Kurulum tamamlandı. Uygulama başlatılıyor..."
python3 hash.py
