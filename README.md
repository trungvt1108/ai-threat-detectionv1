# AI Threat Detection

AI Threat Detection là một console phân tích chạy local. Hệ thống:

- nhận log HTTP / authentication: JSON, NDJSON, log text nginx/Apache (`combined`) và SSH (`auth.log`), cùng Suricata EVE ở mức import/tương quan;
- chuẩn hóa và loại bỏ dữ liệu nhạy cảm **trước khi lưu**;
- gom sự kiện theo cửa sổ thời gian (event-time) cho từng entity;
- chạy song song **rule minh bạch** và **IsolationForest** (scikit-learn);
- tạo alert kèm bằng chứng để người phân tích review;
- đánh giá rules-only / ML-only / hybrid bằng thí nghiệm tái tạo được.

```
log → normalize/redact → time windows/features → rules + IsolationForest → alert/evidence → triage → evaluation/report
```

## Hệ thống không làm gì

- **Không phản ứng tự động.** Không chặn IP, khóa tài khoản, kill process hay sửa firewall. Chỉ có gợi ý kiểm tra bằng lời.
- **Không coi điểm bất thường là bằng chứng tấn công.**
  - `anomaly_score = -IsolationForest.score_samples(X)` là điểm xếp hạng, không phải xác suất.
  - Bách phân vị trên UI là vị trí của điểm trong phân phối điểm của tập train.
- **Không gửi dữ liệu ra ngoài.** Không gọi LLM, không telemetry, không CDN, không email/webhook. Không cần API key.
- **Không phải SIEM/EDR, không phải SaaS.** Một tổ chức, một máy, bind `127.0.0.1`.

## Thành phần

| Phần | Nội dung | Tài liệu |
|---|---|---|
| Nguồn | `http_json`, `http_combined` (nginx/Apache), `auth_json`, `auth_syslog` (sshd); `suricata_eve` (chỉ `alert`/`flow`, mức UPSTREAM_ONLY). Import batch, replay theo timestamp, follow file có checkpoint/rotate/truncate | [docs/SOURCES_AND_SCHEMAS.md](docs/SOURCES_AND_SCHEMAS.md) |
| Privacy | Chỉ giữ trường trong allowlist; scrub secret; chuẩn hóa path (bỏ query); pseudonym HMAC theo key local | [docs/PRIVACY_AND_PUBLISHING.md](docs/PRIVACY_AND_PUBLISHING.md) |
| Features | Hai domain độc lập AUTH / HTTP; feature allowlist tường minh; watermark + late policy | [docs/FEATURE_SPEC.md](docs/FEATURE_SPEC.md) |
| Rules | 10 rule khai báo bằng dữ liệu (threat / operational / health), có version và audit; thiếu trường thì `NOT_EVALUABLE` | [ai_threat_detection/rules/default_rules.json](ai_threat_detection/rules/default_rules.json) |
| ML | IsolationForest cho mỗi domain; registry skops + kiểm tra hash/HMAC/dependency; kích hoạt và rollback có audit | [docs/MODEL_CARD_TEMPLATE.md](docs/MODEL_CARD_TEMPLATE.md) |
| Đánh giá | Split theo thời gian và nhóm capture, purge gap, ngưỡng chọn trên validation, test frozen. `build_dataset` đóng gói log của bạn thành dataset để train | [docs/EVALUATION_PROTOCOL.md](docs/EVALUATION_PROTOCOL.md) |
| Console | Django (tiếng Việt): tổng quan, alert/triage, nguồn, dataset, thí nghiệm, model, drift, báo cáo, jobs, audit | [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) |
| Vận hành | Worker local, retention, backup, rollback, budget tài nguyên | [docs/OPERATIONS.md](docs/OPERATIONS.md) |
| Bảo mật | Threat model và trust boundary | [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) |

## Bắt đầu nhanh

Xem [docs/QUICKSTART.md](docs/QUICKSTART.md) (PowerShell và Linux). Rút gọn:

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\python -m pip install --require-hashes -r requirements\base.lock
.\.venv\Scripts\python manage.py init_local
.\.venv\Scripts\python manage.py migrate
.\.venv\Scripts\python manage.py create_user --username <tên> --role admin
.\.venv\Scripts\python manage.py runserver 127.0.0.1:8815
```

Đưa log thật vào (nginx, SSH `auth.log`, JSON) và train model trên log của chính bạn: xem
[docs/QUICKSTART.md §5](docs/QUICKSTART.md#5-your-own-logs).

## Kết quả đã đo

Chi tiết và giới hạn ở [docs/ACCEPTANCE.md](docs/ACCEPTANCE.md). Các con số chỉ áp dụng cho dữ liệu nêu trong đó:

- dữ liệu tổng hợp (`SYNTHETIC_DEMO`);
- một quan sát lab trên loopback (`LAB_OBSERVED`).

Chúng không phải production validation. Ở một số chỗ, rule baseline tốt hơn ML, và điều đó được báo cáo nguyên trạng.

## Trạng thái

Local v1. Chưa chọn license; xem [CONTRIBUTING.md](CONTRIBUTING.md). Dependencies giữ license gốc của chúng (Django: BSD-3-Clause; scikit-learn: BSD-3-Clause; numpy: BSD-3-Clause; skops: MIT).
