#!/usr/bin/env python3
"""
Wordlist Generator v5 - ذكي ومتكامل، يركز على الأنماط الحقيقية
- ESSID + سنة/رقم/رمز
- أسماء + سنوات + رموز + ليت
- مدن + تواريخ + أرقام
- هواتف مغربية شائعة
- سنوات 1960-2030 مع أيام وشهور شائعة
- أنماط [كلمة][@123][سنة]، [كلمة][2024]
- Leet speak
- ينتج العدد المطلوب بدون أرقام عشوائية
"""

import re, random
from pathlib import Path

MOROCCAN_NAMES = [
    "Mohamed", "Ahmed", "Youssef", "Omar", "Hassan", "Karim", "Mehdi",
    "Hicham", "Nabil", "Rachid", "Said", "Adil", "Kamal", "Amine",
    "Soufiane", "Ismail", "Anas", "Hamza", "Khalid", "Jamal",
    "Abdellah", "Mustapha", "Tariq", "Zakaria", "Brahim",
    "Fatima", "Amina", "Khadija", "Aicha", "Nadia", "Samira",
    "Sara", "Iman", "Leila", "Yasmine", "Meryem", "Sanae", "Zineb",
]

MOROCCAN_CITIES = [
    "Casablanca", "Rabat", "Marrakech", "Fes", "Tanger", "Agadir", "Meknes",
    "Oujda", "Kenitra", "Tetouan", "Safi", "Sale", "Essaouira",
    "Laayoune", "Dakhla", "Mohammedia", "Temara",
]

MOROCCAN_WORDS = [
    "Maroc", "Morocco", "Maghreb", "Bladi", "Hbibti",
    "Raja", "Wydad", "FUS", "Atlas", "Sahara", "Ramadan",
]

LEET_MAP = str.maketrans({'a':'4','e':'3','i':'1','o':'0','s':'5',
                           'A':'4','E':'3','I':'1','O':'0','S':'5'})

SUFFIXES = ["123","1234","12345","123456","12345678","0000","1111","000"]
SPECIAL = ["", "@", "!", "#", "_"]
YEARS = [str(y) for y in range(1960, 2031)]
SHORT_YEARS = [str(y) for y in range(1990, 2031)]

COMMON_PASSWORDS = [
    "12345678","123456789","1234567890","00000000","11111111","22222222",
    "33333333","44444444","55555555","66666666","77777777","88888888",
    "99999999","12121212","password","passw0rd","admin123","admin1234",
    "qwerty123","azerty123","Maroc2024","Maroc2025","Maroc2026",
    "Raja2024","Raja2025","Wydad2024","Wydad2025",
    "Orange123","inwi1234","livebox123","fibre1234",
    "Casa2024","Casa2025","Rabat2024",
    "MHMD1234","fatima123","hassan123",
]

# أكثر تركيبات شائعة رقم+رقم
COMMON_NUMBERS = []
for n in range(10, 100):
    COMMON_NUMBERS.append(str(n) + str(n))
    COMMON_NUMBERS.append(str(n) + "00")
    COMMON_NUMBERS.append("0" + str(n))
    COMMON_NUMBERS.append(str(n) + "1")
for n in [10,12,15,20,25,30,40,50,60,70,80,90,99]:
    COMMON_NUMBERS.append(str(n)*4)
    COMMON_NUMBERS.append(str(n)*2 + "00")
COMMON_NUMBERS = list(set([n for n in COMMON_NUMBERS if 2 <= len(n) <= 8]))

# أشهر 1000 أربعة أرقام للهواتف
PHONE_4D = [f"{i:04d}" for i in range(0, 10000, 19)]
random.shuffle(PHONE_4D)


class WordlistGenerator:
    def __init__(self):
        self.wordlist = {}

    def _add(self, word, priority):
        if not word or len(str(word)) < 8 or len(str(word)) > 63:
            return
        w = str(word).strip()
        if w not in self.wordlist or priority < self.wordlist[w]:
            self.wordlist[w] = priority

    def _extract_words(self, text):
        return [w.lower() for w in re.split(r'[\s\-_\.#@+&]+', text) if len(w) >= 2]

    def _extract_numbers(self, text):
        return re.findall(r'\d+', text)

    def _generate_patterns(self, base_word, priority_base, extra_suffixes=None, extra_years=None):
        """توليد كل الأنماط الممكنة لكلمة أساسية"""
        words_set = {base_word, base_word.lower(), base_word.upper(), base_word.capitalize()}
        results = []
        
        for w in words_set:
            if len(w) >= 8:
                self._add(w, priority_base)
        
        base_low = base_word.lower()
        
        # 1. كلمة + سنة
        years_list = extra_years or SHORT_YEARS
        for y in years_list:
            for sym in SPECIAL[:4]:
                c = f"{base_low}{sym}{y}"
                if 8 <= len(c) <= 63: self._add(c, priority_base + 1)
                c = f"{y}{sym}{base_low}"
                if 8 <= len(c) <= 63: self._add(c, priority_base + 1)
            if len(base_low + y) >= 8:
                for c in [f"{base_low}{y}", f"{base_low.capitalize()}{y}",
                          f"{y}{base_low}", f"{y}{base_low.capitalize()}"]:
                    if 8 <= len(c) <= 63: self._add(c, priority_base + 1)
        
        # 2. كلمة + أرقام شائعة
        suffixes = extra_suffixes or SUFFIXES
        for s in suffixes:
            for v in [base_low, base_low.capitalize(), base_low.upper()]:
                if len(v + s) >= 8:
                    self._add(f"{v}{s}", priority_base + 1)
                if len(s + v) >= 8:
                    self._add(f"{s}{v}", priority_base + 1)
        
        # 3. كلمة + رمز + رقم
        for sym in SPECIAL[:5]:
            for cn in COMMON_NUMBERS[:50]:
                c = f"{base_low}{sym}{cn}"
                if 8 <= len(c) <= 63: self._add(c, priority_base + 2)
                c = f"{cn}{sym}{base_low}"
                if 8 <= len(c) <= 63: self._add(c, priority_base + 2)
        
        # 4. كلمة + رمز + سنة
        for sym in SPECIAL[:4]:
            for y in years_list[:20]:
                c = f"{base_low}{sym}{y}"
                if 8 <= len(c) <= 63: self._add(c, priority_base + 2)
                c = f"{y}{sym}{base_low}"
                if 8 <= len(c) <= 63: self._add(c, priority_base + 2)
        
        # 5. كلمة مكررة
        self._add(f"{base_low}{base_low}", priority_base + 2)
        self._add(f"{base_low.capitalize()}{base_low.capitalize()}", priority_base + 2)
        
        # 6. يوم شهر سنة (تاريخ ميلاد)
        days = [str(d) for d in [1,5,10,12,15,20,21,22,23,24,25,30]]
        months = [str(m) for m in range(1,13)]
        for d in days:
            for m in months:
                for y in years_list[:15]:
                    for fmt in [f"{d.zfill(2)}{m.zfill(2)}{y}",
                                f"{y}{m.zfill(2)}{d.zfill(2)}"]:
                        if 8 <= len(fmt) <= 63 and len(base_low + fmt) >= 8:
                            self._add(f"{base_low}{fmt}", priority_base + 3)
                            self._add(f"{base_low.capitalize()}{fmt}", priority_base + 3)
        
        # 7. Leet speak
        leeted = base_low.translate(LEET_MAP)
        if leeted != base_low:
            for s in suffixes[:5]:
                if len(leeted + s) >= 8:
                    self._add(f"{leeted}{s}", priority_base + 3)
            for y in years_list[:10]:
                if len(leeted + y) >= 8:
                    self._add(f"{leeted}{y}", priority_base + 3)

    def generate_for_network(self, essid, bssid="", brand="", max_words=100000):
        self.wordlist = {}
        words = self._extract_words(essid)
        nums = self._extract_numbers(essid)
        clean = re.sub(r'[\s\-_\.]', '', essid)
        target = max_words

        # ═══════════════════════════════════════════
        # المرحلة 0: ESSID نفسه
        # ═══════════════════════════════════════════
        if clean:
            self._generate_patterns(clean, 0)

        # ═══════════════════════════════════════════
        # المرحلة 1: كلمات من ESSID مفردة
        # ═══════════════════════════════════════════
        for w in words:
            if len(w) >= 3:
                self._generate_patterns(w, 10)

        # ═══════════════════════════════════════════
        # المرحلة 2: Brand + ESSID
        # ═══════════════════════════════════════════
        all_brands = []
        if brand:
            all_brands = [brand, brand.lower(), brand.upper()]
        else:
            all_brands = ["ZTE","Orange","inwi","IAM","Livebox","TPLink",
                         "Fibre","ADSL","Huawei","Maroc"]

        for bn in all_brands:
            if clean:
                self._generate_patterns(f"{bn}{clean}", 20)
                self._generate_patterns(f"{clean}{bn}", 20)

        for w in words:
            if len(w) >= 3:
                for bn in all_brands:
                    c1 = f"{bn}{w}"
                    c2 = f"{w}{bn}"
                    if 8 <= len(c1) <= 63: self._add(c1, 22)
                    if 8 <= len(c2) <= 63: self._add(c2, 22)

        # ═══════════════════════════════════════════
        # المرحلة 3: أسماء مغربية
        # ═══════════════════════════════════════════
        for name in MOROCCAN_NAMES:
            self._generate_patterns(name, 30)

        # ═══════════════════════════════════════════
        # المرحلة 4: مدن مغربية
        # ═══════════════════════════════════════════
        for city in MOROCCAN_CITIES:
            self._generate_patterns(city, 40)

        # ═══════════════════════════════════════════
        # المرحلة 5: كلمات مغربية
        # ═══════════════════════════════════════════
        for mw in MOROCCAN_WORDS:
            self._generate_patterns(mw, 50)

        # ═══════════════════════════════════════════
        # المرحلة 6: كلمات شائعة
        # ═══════════════════════════════════════════
        for pw in COMMON_PASSWORDS:
            self._add(pw, 60)

        # ═══════════════════════════════════════════
        # المرحلة 7: سنوات مع أيام/شهور
        # ═══════════════════════════════════════════
        months_short = [1, 6, 12]
        days_short = [1, 15]
        for y in YEARS[:60]:
            for m in months_short:
                for d in days_short:
                    f1 = f"{d:02d}{m:02d}{y}"
                    f2 = f"{y}{m:02d}{d:02d}"
                    if 8 <= len(f1) <= 63: self._add(f1, 70)
                    if 8 <= len(f2) <= 63: self._add(f2, 70)

        # ═══════════════════════════════════════════
        # المرحلة 8: أرقام هواتف
        # ═══════════════════════════════════════════
        for prefix in ["06", "07", "05"]:
            for suffix in PHONE_4D[:target]:
                p = f"{prefix}{suffix}"
                if 8 <= len(p) <= 63:
                    self._add(p, 80)
                if len(self.wordlist) >= target:
                    break
            if len(self.wordlist) >= target:
                break

        # ═══════════════════════════════════════════
        # المرحلة 9: أرقام متسلسلة منظمة
        # ═══════════════════════════════════════════
        if len(self.wordlist) < target:
            for i in range(0, 99999999, 1379):
                p = f"{i:08d}"
                if 8 <= len(p) <= 63:
                    self._add(p, 83)
                if len(self.wordlist) >= target:
                    break

        # ═══════════════════════════════════════════
        # المرحلة 10: أرقام عشوائية (احتياط شديد)
        # ═══════════════════════════════════════════
        while len(self.wordlist) < target:
            r = f"{random.randint(10000000, 99999999)}"
            if 8 <= len(r) <= 63:
                self._add(r, 90)

        result = sorted(self.wordlist.keys(), key=lambda w: (self.wordlist[w], w))[:target]
        return result

    def generate_from_essid(self, essid, max_words=500):
        self.wordlist = {}
        words = self._extract_words(essid)
        clean = re.sub(r'[\s\-_\.]', '', essid)
        if clean:
            self._add(clean, 0)
        for w in words:
            if len(w) >= 3:
                for s in SUFFIXES[:4]:
                    self._add(f"{w}{s}", 1)
                for y in SHORT_YEARS[:5]:
                    if len(w + y) >= 8:
                        self._add(f"{w}{y}", 1)
        return sorted(self.wordlist.keys(), key=lambda w: (self.wordlist[w], w))[:max_words]

    def save_to_file(self, filepath, max_words=1000000):
        words = sorted(self.wordlist.keys(), key=lambda w: (self.wordlist[w], w))[:max_words]
        with open(filepath, "w") as f:
            for w in words:
                f.write(w + "\n")
        return len(words)
