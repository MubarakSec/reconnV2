# 🔍 ReconnV2 - Advanced Reconnaissance Pipeline

<div align="center">

![Python](https://img.shields.io/badge/Python-3.10+-blue.svg)
![Kali](https://img.shields.io/badge/Kali-Linux-557C94.svg)
![Docker](https://img.shields.io/badge/Docker-Ready-2496ED.svg)
![License](https://img.shields.io/badge/License-MIT-green.svg)

**أداة استطلاع أمني متقدمة ومؤتمتة لاكتشاف الثغرات والأصول**

[التثبيت](#-التثبيت-السريع) •
[الاستخدام](#-الاستخدام) •
[الواجهات](#-طرق-الاستخدام-المتعددة) •
[المراحل](#-مراحل-الفحص) •
[Docker](#-docker)

</div>

---

## 📁 هيكل المشروع

```
reconnV2/
├── 📜 install.sh          # سكربت التثبيت التلقائي
├── 📜 recon.sh             # واجهة تفاعلية بالعربية
├── 📜 quick-scan.sh        # فحص سريع بأمر واحد
├── 📜 wizard.py            # معالج تفاعلي بواجهة ملونة
├── 📜 cheatsheet.sh        # مرجع سريع للأوامر
├── 📜 Makefile             # أوامر Make مختصرة
├── 🐳 Dockerfile           # صورة Docker
├── 🐳 docker-compose.yml   # تكوين Docker Compose
├── 📁 recon_cli/           # الكود الرئيسي
├── 📁 config/              # ملفات التكوين
├── 📁 jobs/                # نتائج الفحص
└── 📁 tests/               # الاختبارات
```

---

## ⚡ التثبيت السريع (Kali Linux)

### الطريقة 1: التثبيت التلقائي (موصى به)
```bash
# استنساخ المشروع
git clone https://github.com/your-repo/reconnV2.git
cd reconnV2

# تشغيل سكربت التثبيت
chmod +x install.sh recon.sh quick-scan.sh cheatsheet.sh
./install.sh
```

### الطريقة 2: التثبيت اليدوي
```bash
# إنشاء بيئة افتراضية
python3 -m venv .venv
source .venv/bin/activate

# تثبيت المشروع
pip install -e .

# تثبيت الأدوات الخارجية
sudo apt install subfinder amass nuclei httpx-toolkit
```

### الطريقة 3: Docker
```bash
docker build -t reconnv2 .
docker run -it reconnv2 --help
```

---

## 🎮 طرق الاستخدام المتعددة

### 1️⃣ الواجهة التفاعلية بالعربية (الأسهل)
```bash
./recon.sh
```
تفتح قائمة تفاعلية سهلة الاستخدام:
```
╔═══════════════════════════════════════╗
║          القائمة الرئيسية             ║
╠═══════════════════════════════════════╣
║ [1] 🔍 فحص سريع (Quick Scan)          ║
║ [2] 🎯 فحص سلبي (Passive Scan)        ║
║ [3] 🚀 فحص شامل (Full Scan)           ║
║ [4] 🔬 فحص عميق (Deep Scan)           ║
║ [5] 🐛 فحص Bug Bounty                 ║
║ ...                                   ║
╚═══════════════════════════════════════╝
```

### 2️⃣ المعالج التفاعلي (Python)
```bash
source .venv/bin/activate
python wizard.py
```
واجهة ملونة مع خيارات متقدمة!

### 3️⃣ الفحص السريع
```bash
# فحص بسيط
./quick-scan.sh target.com

# فحص مع خيارات
./quick-scan.sh target.com -p full -s nuclei

# فحص Bug Bounty
./quick-scan.sh target.com -p bugbounty -s nuclei -a js-secrets
```

### 4️⃣ أوامر Make
```bash
make help                      # عرض المساعدة
make install                   # تثبيت
make scan TARGET=target.com    # فحص
make scan-full TARGET=target.com
make scan-quick TARGET=target.com
make jobs                      # عرض المهام
make doctor                    # فحص النظام
```

### 5️⃣ سطر الأوامر المباشر
```bash
source .venv/bin/activate
recon-cli scan target.com --profile passive --inline
```

### 6️⃣ عرض المرجع السريع
```bash
./cheatsheet.sh
```

---

## 🚀 الأوامر الأساسية

```bash
# تفعيل البيئة أولاً
source .venv/bin/activate

# فحص سريع
recon-cli scan example.com --inline

# فحص سلبي (آمن)
recon-cli scan example.com --profile passive --inline

# فحص شامل
recon-cli scan example.com --profile full --inline

# فحص عميق مع nuclei
recon-cli scan example.com --profile deep --scanner nuclei --inline

# فحص متعدد الأهداف
recon-cli scan --targets-file targets.txt --profile deep --inline
```

---

## 📋 الملفات الشخصية (Profiles)

| الملف | الوصف | الاستخدام |
|-------|-------|-----------|
| `passive` | فحص سلبي آمن، لا يُكتشف | الاستكشاف الأولي |
| `full` | فحص نشط وشامل | الفحص الكامل |
| `quick` | فحص سريع وخفيف | نظرة سريعة |
| `deep` | فحص عميق ومكثف | تحليل شامل |
| `bugbounty` | مُحسَّن لصيد الثغرات | Bug Bounty |
| `stealth` | فحص خفي وبطيء | تجنب الاكتشاف |
| `api-only` | APIs و GraphQL فقط | فحص APIs |
| `wordpress` | مُحسَّن لـ WordPress | مواقع WP |

---

## 🔧 خيارات الفحص

| الخيار | الوصف | مثال |
|--------|-------|------|
| `--profile` | نوع الفحص | `--profile deep` |
| `--inline` | تشغيل فوري | `--inline` |
| `--targets-file` | ملف الأهداف | `--targets-file list.txt` |
| `--scanner` | ماسح إضافي | `--scanner nuclei` |
| `--active-module` | وحدة نشطة | `--active-module js-secrets` |
| `--force` | إعادة كل المراحل | `--force` |
| `--quickstart` | أسرع فحص | `--quickstart` |
| `-v` / `-vv` | زيادة التفاصيل | `-vv` |

---

## 🎯 أمثلة عملية

### استطلاع سلبي بسيط
```bash
recon-cli scan target.com --profile passive --inline
```

### فحص مع اكتشاف الأسرار
```bash
recon-cli scan target.com --active-module js-secrets --inline
```

### فحص شامل مع Nuclei
```bash
recon-cli scan target.com --profile full --scanner nuclei --inline
```

### فحص WordPress
```bash
recon-cli scan wordpress-site.com --profile wordpress --scanner wpscan --inline
```

### فحص قائمة أهداف
```bash
# إنشاء ملف الأهداف
cat > targets.txt << EOF
target1.com
target2.com
target3.com
EOF

# تشغيل الفحص
recon-cli scan --targets-file targets.txt --profile deep --inline
```

### فحص Bug Bounty الكامل
```bash
recon-cli scan bugbounty-target.com \
    --profile bugbounty \
    --scanner nuclei \
    --active-module js-secrets \
    --active-module backup \
    --inline
```

### فحص خفي (Stealth)
```bash
recon-cli scan sensitive-target.com --profile stealth --inline
```

---

## 🔄 مراحل الفحص

```
┌─────────────────────────────────────────────────────────┐
│  1. Normalize      → تطبيع الأهداف                      │
│  2. Passive Enum   → اكتشاف النطاقات الفرعية            │
│  3. Dedupe         → إزالة المكرر                       │
│  4. DNS Resolve    → حل عناوين DNS                     │
│  5. Enrichment     → إثراء البيانات                     │
│  6. HTTP Probe     → فحص خدمات HTTP                    │
│  7. Scoring        → تقييم المخاطر                      │
│  8. IDOR Check     → فحص ثغرات IDOR                    │
│  9. Auth Matrix    → فحص التراخيص                      │
│ 10. Fuzzing        → الفحص بالقوة الغاشمة               │
│ 11. Active Intel   → الاستطلاع النشط                    │
│ 12. Secrets        → اكتشاف الأسرار                     │
│ 13. Runtime Crawl  → الزحف التفاعلي                    │
│ 14. Correlation    → ربط النتائج                       │
│ 15. Learning       → التعلم الآلي                       │
│ 16. Scanner        → Nuclei/WPScan                     │
│ 17. Screenshots    → لقطات الشاشة                      │
│ 18. Finalize       → إنهاء وتقرير                       │
└─────────────────────────────────────────────────────────┘
```

---

## 🛠️ إدارة المهام

```bash
# عرض المهام
recon-cli list-jobs
recon-cli list-jobs --status running

# عرض حالة مهمة
recon-cli status <job-id>

# متابعة السجلات
recon-cli tail-logs <job-id>

# إعادة تشغيل مهمة فاشلة
recon-cli requeue <job-id>

# تصدير النتائج
recon-cli export <job-id> --format json
recon-cli export <job-id> --format txt

# إنشاء تقرير
recon-cli report <job-id>

# فحص النظام
recon-cli doctor

# تنظيف المهام القديمة
recon-cli prune --days 7
```

---

## 📁 هيكل النتائج

```
jobs/finished/<job-id>/
├── metadata.json      # بيانات المهمة
├── spec.json          # مواصفات الفحص
├── results.jsonl      # النتائج (JSON Lines)
├── results.txt        # النتائج (نص)
├── artifacts/         # الملفات المستخرجة
│   ├── targets.txt
│   ├── subfinder.txt
│   ├── amass.json
│   ├── httpx.json
│   └── ...
└── logs/
    └── pipeline.log   # سجل التنفيذ
```

---

## 🐳 Docker

### بناء الصورة
```bash
docker build -t reconnv2 .
```

### تشغيل فحص
```bash
# فحص سريع
docker run -v $(pwd)/jobs:/app/jobs reconnv2 scan target.com --inline

# فحص تفاعلي
docker run -it -v $(pwd)/jobs:/app/jobs reconnv2 scan target.com --profile full --inline
```

### Docker Compose
```bash
# تشغيل
docker-compose run recon scan target.com --inline

# عرض المهام
docker-compose run recon list-jobs
```

---

## 🔧 التكوين

### ملفات التعريف (`config/profiles.json`)

```json
{
  "quick": {
    "base_profile": "passive",
    "description": "فحص سريع وخفيف",
    "runtime": {
      "enable_fuzz": false,
      "enable_secrets": true
    }
  },
  "bugbounty": {
    "base_profile": "full",
    "description": "مُحسَّن لصيد الثغرات",
    "runtime": {
      "enable_fuzz": true,
      "enable_runtime_crawl": true,
      "enable_screenshots": true
    }
  }
}
```

### DNS Resolvers (`config/resolvers.txt`)
```
1.1.1.1
8.8.8.8
9.9.9.9
```

---

## 📦 الأدوات المطلوبة

| الأداة | الوظيفة | التثبيت |
|--------|---------|---------|
| subfinder | اكتشاف النطاقات | `apt install subfinder` |
| amass | استطلاع شامل | `apt install amass` |
| httpx | فحص HTTP | `apt install httpx-toolkit` |
| nuclei | فحص الثغرات | `apt install nuclei` |
| wpscan | فحص WordPress | `apt install wpscan` |
| waybackurls | URLs التاريخية | `go install github.com/tomnomnom/waybackurls@latest` |
| gau | URLs إضافية | `go install github.com/lc/gau/v2/cmd/gau@latest` |

---

## 🔥 One-Liners سريعة

```bash
# اكتشاف سريع للنطاقات الفرعية
recon-cli scan target.com -p passive --inline 2>/dev/null | grep hostname

# فحص وعرض النتائج مباشرة
JOB=$(recon-cli scan target.com -p quick --inline 2>&1 | grep -oP 'Job \K\S+')
cat jobs/finished/$JOB/results.txt

# عرض آخر نتائج
cat jobs/finished/$(ls -t jobs/finished/ | head -1)/results.txt

# فحص قائمة من stdin
echo -e "site1.com\nsite2.com" | tee targets.txt && \
    recon-cli scan --targets-file targets.txt --inline
```

---

## 🎯 نصائح للاستخدام

1. **ابدأ بـ passive** - دائماً ابدأ بالفحص السلبي للاستكشاف
2. **استخدم الواجهة التفاعلية** - `./recon.sh` للمبتدئين
3. **راجع cheatsheet** - `./cheatsheet.sh` للمرجع السريع
4. **تابع السجلات** - `tail-logs` لمتابعة التقدم
5. **استخدم --force** - لإعادة الفحص من البداية
6. **نظف المهام** - `prune --days 7` بانتظام

---

## 🐛 استكشاف الأخطاء

```bash
# فحص النظام والأدوات
recon-cli doctor

# تشغيل مع تفاصيل أكثر
recon-cli scan target.com -vv --inline

# التحقق من التثبيت
python -c "import recon_cli; print('OK')"
```

---

## 📄 License

MIT License - استخدم بمسؤولية وأخلاقية فقط.

---

<div align="center">

### ⚠️ تحذير مهم

**استخدم هذه الأداة فقط على الأنظمة التي لديك إذن صريح باختبارها**

الاستخدام غير المصرح به يُعد انتهاكاً للقانون

---

Made with ❤️ for Security Researchers

</div>
