# Meta-Guardian — Uygulama Planı v2 (İlerleme İşaretli)

Takvim: 1 Kasım akşamı FEATURE FREEZE. Teslim 4 Kasım 16:00 TR.
Test: `python -m pytest -q` — her görev sonunda TAMAMEN yeşil + TEK commit.
Durma kuralı: süre %50 aşarsa dur, yarım iş commit edilmez, raporla.

> **FEATURE FREEZE (31 Ekim 2026).** Sekiz görevin tamamı kapandı. Bundan sonra
> yalnızca uçtan uca (E2E) doğrulamadan çıkan hata düzeltmeleri commit edilir;
> yeni özellik, yeni senaryo ve yeni bağımlılık eklenmez. Kapsam dışı listesi
> aynen geçerlidir.
>
> Freeze sonrası yapılan iki düzeltme bu kuralın kapsamındadır (ikisi de Docker
> E2E'de bulundu): `trigger_attack.py` artık `TRUST_FORWARDED_FOR=1` iken kokpitin
> `fire_attack`'i gibi demo saldırgan IP'sini gönderiyor (yoksa kaynak loopback
> olduğu için hiçbir aksiyon önerilmiyordu), ve `benchmark_baseline.py` senaryo
> C'nin olaylarına oturum kimliği ekledi (bilet sahibi eşleşmeyince C
> `BENIGN_AUTHORIZED` yerine `BENIGN_UNKNOWN` çıkıyordu).

## Ortak kurallar
- Yeni bağımlılık YOK (stdlib + mevcut requirements.txt).
- Donmuş: `backend/edge/correlator.py`, OODA/forensics prompt ŞABLONLARI (metinleri),
  `sam_bridge.py` tier sırası. (`ooda_agent.py` içindeki `build_evidence` ve
  `_fallback_decision` değişebilir — donmuş olan sadece mesaj şablonları.)
- `policy_engine.py` görev 4'te tekrar dokunulacak (doğrulanmış açık kapatılıyor).
- Testlerde gerçek ağ/anahtar yok.

## Durum

| # | Görev | Durum |
|---|---|---|
| 1 | S2: Kokpit auth + onaycı kimliği | ✅ 645276a |
| 2 | A1: Bilet ↔ oturum sahibi ↔ rol bağı + audit enrichment | ✅ fb22509 |
| 3 | S1: Kamera tamper tespiti, fail-closed | ✅ 0d4a399 |
| 4 | A2: Konsol çakışması / CREDENTIAL_MISUSE | ✅ |
| 5 | A3: Append-only hash ledger | ✅ |
| 6 | S3-lite: Deterministik fallback (fail-open kapat) | ✅ |
| 7 | S5: Kare saklama süresi | ✅ |
| 8 | A4: ATT&CK eşlemesi | ✅ |

## Görev 4 — A2: CREDENTIAL_MISUSE (~3 saat, durma kuralı aktif)

KOŞULLAR (kesin):
- CREDENTIAL_MISUSE = admin komut + masa DOLU + origin UZAK
  (localhost değil VE management networkleri dışından). Origin koşulu olmadan
  masadaki her yerel admin işlemi yanlış sınıflanır!
- Ghost kuralı değişiyor: bilet sahibi == oturum sahibi VE origin yönetim
  ağından VE masa boş → BENIGN_AUTHORIZED (meşru uzaktan IT).
  GHOST = admin + masa boş + (bilet yok VEYA bilet sahibi ≠ oturum sahibi).
- CREDENTIAL_MISUSE asla AUTO'ya düşmez → daima APPROVAL
  (sinyal çelişki, kanıt değil).

Durum tablosu (birebir test edilecek):
| Durum | Kamera | Beklenen |
|---|---|---|
| bilet sahibi = oturum sahibi + origin mgmt, masa boş | boş | BENIGN_AUTHORIZED |
| bilet yok, masa dolu, admin, origin uzak | dolu | CREDENTIAL_MISUSE + APPROVAL |
| bilet yok, masa boş, admin | boş | GHOST_ATTACK + AUTO |
| bilet yok, masa dolu, admin YEREL origin | dolu | mevcut davranış (THREAT_CRITICAL) |

Yapılacaklar:
1. `backend/models.py`: `Classification.CREDENTIAL_MISUSE` (mevcutları bozmadan).
2. `backend/edge/ooda_agent.py`: `build_evidence`'a oturum sahibi/rol/origin;
   `_scenario_for`'a yeni sınıf.
3. `backend/edge/policy_engine.py`: yukarıdaki koşullar; kural sırasına dikkat.
4. `backend/config.py`: `management_networks: str` (env `MG_MANAGEMENT_NETWORKS`,
   virgülle CIDR, default boş). Origin bu aralıktaysa reason'a
   "known management source".
5. DEMO-KRİTİK: `backend/llm/mock.py`'ye yeni sınıf pattern'i + gerekirse
   `data/fixtures/ooda_*.json` replay kaydı. Bu olmadan mock/replay demo
   yeni senaryoyu gösteremez.
6. Frontend + casefile: yeni sınıf etiketi + origin bilgisi.

Test: `tests/test_policy_engine.py` (~8: tablo 4 satır + eşikler),
`tests/test_ooda_agent.py` (~3), `tests/test_gateway_security.py` (origin).
test_ticket_ownership.py dahil mevcut testler yeşil kalmalı (regression).

## Görev 5 — A3: Append-only hash ledger (~1 saat)

TASARIM UYARISI: Hash'i casefile üretiminden ALMA — approve() incident'ı
sonradan değiştirir, zincir false-positive "tampered" verir.

Doğru tasarım:
1. `backend/casefile.py`: `data/runtime/` altında append-only ledger
   (`hashchain.jsonl`). Her `_persist` çağrısında satır eklenir:
   `{"incident_id", "content_sha256", "prev_sha256", "recorded_at", "kind"}`
   (kind: created/updated — approve/reject meşru güncellemedir, YENİ satır).
2. Content hash: incident'ın kanonik JSON'undan
   (`json.dumps(..., sort_keys=True, separators=(",", ":"))`) sha256.
3. `GET /api/incidents/{id}/casefile?format=json&verify=1`: güncel içerik
   hash'i o incident'ın ledger'daki EN SON satırıyla eşleşiyor mu →
   chain_valid + hangi satırda kırıldı.
4. Markdown'da "Integrity" bölümü.

Kabul: hash deterministik; diskteki incident elle değiştirilirse chain_valid=false;
approve/reject sonrası zincir KIRILMAZ (yeni satır, chain_valid=true kalır).
Test: tests/test_casefile.py (~5).

## Görev 6 — S3-lite: Deterministik fallback (~1 saat)

Sorun: LLM kapalı + USB + exfil → BENIGN_UNKNOWN → MONITOR → DISMISSED, sıfır
aksiyon (fail-open). (Admin + boş koltuk yolu zaten deterministik GHOST + AUTO — korunur.)

Yapılacak:
1. `ooda_agent._fallback_decision()`: olaylarda exfil/SQLi/missing_session işareti
   varsa → THREAT_CRITICAL + confidence 0.55 (APPROVAL bandı). Sadece USB/benign →
   mevcut davranış.
2. Frontend: model adı "fallback" iken amber DEGRADED rozeti.

Kabul: LLM kapalı + exfil → APPROVAL + pending aksiyonlar, sıfır sessiz dismiss.
Test: tests/test_ooda_agent.py (~4) + pipeline uç durumu.

## Görev 7 — S5: Kare saklama süresi (~1 saat)

1. `backend/config.py`: `frame_retention_days: int` (env
   `MG_FRAME_RETENTION_DAYS`, default 7).
2. `backend/main.py`: başlangıçta + günde bir: `data/runtime/evidence/*/frame.png`
   süresi geçmişse sil. MASKE + sha256 KALIR. retention=0 → silme.
3. `GET /api/config` politikayı gösterir; THREAT_MODEL + README veri akışı:
   "kare → segmentasyon ucu, LLM'e gitmez, N gün sonra silinir, kalıcı olan
   maske + hash".
Test: tmp dizinde yaşlanmış kare silinir / maske kalır / retention=0 silmez.

## Görev 8 — A4: ATT&CK eşlemesi (~45 dk)

1. `backend/models.py`: sabit sözlük — GHOST_ATTACK → T1078,
   CREDENTIAL_MISUSE → T1078, USB → T1200, exfil → T1567, KILL_PROCESS → T1489.
2. Casefile'a `attack_techniques: list[str]`; kokpitte kartta teknik rozeti.
3. THREAT_MODEL.md eşleme tablosu.
Kabul: her sınıflandırma ≥ 1 teknik; casefile'da görünür.
