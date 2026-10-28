"""Model card generation (Markdown) from registry metadata. Stored next to the
artifact under ``<data_dir>/models``; not public by default."""

from __future__ import annotations

from typing import Any

from ai_threat_detection.registry.models import ModelVersion
from ai_threat_detection.registry.service import models_root


def fmt(v: Any, pct: bool = False) -> str:
    if v is None:
        return "N/A"
    if isinstance(v, float):
        return f"{v * 100:.1f}%" if pct else f"{v:.4f}"
    return str(v)


def metrics_table(m: dict[str, Any], task: str = "T1_SUSPICIOUS") -> str:
    t = (m.get("tasks") or {}).get(task)
    if not t:
        return "_Chưa có._\n"
    rows = [
        "| Phương pháp | Precision | Recall | F1 | TP | FP | FN | TN | FP/1000 neg windows | Alerts (grouped) |",
        "|---|---|---|---|---|---|---|---|---|---|",
    ]
    for name, r in t["methods"].items():
        g = r.get("grouped_alerts", {})
        rows.append(
            f"| {name} | {fmt(r['precision'], True)} | {fmt(r['recall'], True)} | {fmt(r['f1'], True)} | "
            f"{r['tp']} | {r['fp']} | {r['fn']} | {r['tn']} | {fmt(r.get('fp_per_1000_negative_windows'))} | "
            f"{g.get('total', 'N/A')} ({g.get('without_positive_window', 'N/A')} không chứa positive) |"
        )
    mr = t.get("ml_ranking", {})
    rows.append("")
    rows.append(
        f"Support: {t['methods']['rules_only']['support_positive']} positive / "
        f"{t['methods']['rules_only']['support_negative']} negative windows; "
        f"{t['units_excluded_unknown_label']} UNKNOWN bị loại. Average precision (ML score, {mr.get('support_scored')} "
        f"windows được chấm): {fmt(mr.get('value'))}; ML abstain: {mr.get('abstained_windows')}."
    )
    return "\n".join(rows) + "\n"


def render_model_card(mv: ModelVersion) -> str:
    hp = mv.hyperparameters
    crit = mv.threshold_criterion
    exp = mv.experiment
    ds = exp.dataset if exp else None
    lines = [
        f"# Model card — {mv.model_id}",
        "",
        f"- **Domain:** {mv.domain} (chỉ dùng cho cửa sổ {mv.domain}; không dùng cho domain/schema khác)",
        f"- **Thuật toán:** {mv.algorithm} (scikit-learn {mv.dependencies.get('scikit-learn')}), unsupervised novelty detection",
        f"- **Trạng thái:** {mv.status}",
        f"- **Feature set:** {mv.feature_set} / {mv.feature_schema_version}",
        f"- **Feature order:** {', '.join(mv.feature_order)}",
        f"- **Transforms (stateless):** {', '.join(f'{k}:{v}' for k, v in mv.transforms.items())}",
        f"- **Window:** {mv.window_config.get('kind')} size={mv.window_config.get('size_s')}s stride={mv.window_config.get('stride_s')}s "
        f"lateness={mv.window_config.get('allowed_lateness_s')}s (cfg {mv.cfg_hash})",
        f"- **Hyperparameters:** {hp}; random_state={mv.random_state}",
        f"- **Artifact:** {mv.artifact_format}, sha256 {mv.artifact_sha256[:16]}…, integrity key id {mv.integrity_key_id}",
        f"- **Dependencies:** {mv.dependencies}",
        "",
        "## Intended use",
        "Hỗ trợ triage: xếp hạng các cửa sổ entity có hành vi lệch khỏi baseline đã chọn, để analyst xem xét cùng với rule.",
        "Không xác nhận incident, actor, CVE hay việc tấn công thành công. Không dùng cho phản ứng tự động.",
        "",
        "## Dữ liệu và phương pháp",
        f"- Dataset: {ds.dataset_id if ds else 'N/A'} — provenance {ds.provenance if ds else 'N/A'}, privacy {ds.privacy_class if ds else 'N/A'}",
        f"- Experiment: {exp.exp_id if exp else 'N/A'}; split manifest sha256 {mv.split_manifest_sha256[:16]}…",
        f"- Train: {mv.n_train} cửa sổ đủ điều kiện, cutoff {mv.train_cutoff}; loại trừ: {mv.train_exclusions}",
        "- Giả định: tập train là hoạt động nền đã chọn có căn cứ (kịch bản baseline được điều khiển). "
        "Nếu baseline lẫn hoạt động bất thường (contamination), model có thể coi chúng là bình thường.",
        f"- Hyperparameter trials (chọn theo validation AP): {mv.hyperparameter_trials}",
        "",
        "## Score semantics",
        f"- {mv.score_transform}",
        "- Đây là điểm xếp hạng bất thường, **không phải xác suất bị tấn công**. "
        "`contamination='auto'` không được diễn giải là tỷ lệ dữ liệu độc hại.",
        "- Bách phân vị hiển thị trong UI = vị trí của score trong phân phối score của tập train (101 quantiles).",
        f"- **Operating threshold:** {mv.threshold:.4f} (version {mv.threshold_version}); tiêu chí: {crit}",
        "",
        "## Kết quả validation (dùng để chọn threshold/hyperparameters)",
        metrics_table(mv.validation_metrics),
        "## Kết quả test (frozen, chỉ báo cáo)",
        metrics_table(mv.test_metrics) if mv.test_metrics else "_Chưa chạy evaluate trên test._\n",
        "## Limitations / known false positives",
        "- Lỗi vận hành (5xx, latency tăng) và tải hợp lệ tăng (batch job) là bất thường thống kê và có thể bị gắn cờ dù không độc hại.",
        "- Tấn công chậm (low-and-slow) dưới mức biến thiên nền của một cửa sổ thường không bị phát hiện.",
        "- Cửa sổ ít sự kiện có vector feature trùng nhau nhiều; điểm của chúng kém phân biệt.",
        "- Thiếu trường (status/method/bytes/duration hoặc outcome) → ML abstain (INSUFFICIENT_DATA), không coi là rủi ro thấp.",
        f"- {(mv.test_metrics or mv.validation_metrics or {}).get('caveat', '')}",
        "",
        "## Provenance",
        f"- Tạo lúc {mv.created_at:%Y-%m-%d %H:%M} UTC bởi {mv.created_by or 'system'}; pseudonym key id {mv.pseudonym_key_id}.",
        "- Artifact và baseline học từ dữ liệu riêng mặc định chỉ lưu local (.local), không public.",
        "",
    ]
    return "\n".join(lines)


def write_model_card(mv: ModelVersion) -> str:
    rel = f"{mv.domain.lower()}/{mv.model_id}/MODEL_CARD.md"
    path = models_root() / rel
    path.write_text(render_model_card(mv), encoding="utf-8")
    mv.model_card_rel = rel
    mv.save(update_fields=["model_card_rel"])
    return rel
