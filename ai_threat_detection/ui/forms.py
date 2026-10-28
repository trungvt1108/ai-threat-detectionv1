from __future__ import annotations

from django import forms

from ai_threat_detection.alerts.models import Assessment, WorkflowStatus
from ai_threat_detection.sources.models import PrivacyClass, Provenance, SourceType


class SourceForm(forms.Form):
    name = forms.SlugField(max_length=64, label="Tên (slug)")
    source_type = forms.ChoiceField(choices=SourceType.choices, label="Loại nguồn")
    root_path = forms.CharField(max_length=1024, label="Thư mục gốc (trong ATD_ALLOWED_SOURCE_ROOTS)")
    file_pattern = forms.CharField(
        max_length=128,
        required=False,
        label="Mẫu tên file (để trống: *.ndjson cho JSON, * cho log text)",
    )
    provenance = forms.ChoiceField(choices=Provenance.choices, initial=Provenance.USER_IMPORTED)
    privacy_class = forms.ChoiceField(choices=PrivacyClass.choices, initial=PrivacyClass.PRIVATE)
    assume_timezone = forms.CharField(
        max_length=64, required=False, label="Timezone giả định cho timestamp thiếu offset"
    )
    sensor_name = forms.CharField(max_length=64, initial="default")
    stale_after_seconds = forms.IntegerField(min_value=30, max_value=7 * 86400, initial=900)
    expected_max_gap_seconds = forms.IntegerField(min_value=1, max_value=7 * 86400, required=False)
    license_note = forms.CharField(max_length=500, required=False)
    reason = forms.CharField(max_length=500, min_length=5, label="Lý do (audit)")

    def clean_file_pattern(self):
        v = self.cleaned_data["file_pattern"].strip()
        if "/" in v or "\\" in v or ".." in v:
            raise forms.ValidationError("chỉ mẫu tên file, không chứa đường dẫn")
        return v


class SourceJobForm(forms.Form):
    action = forms.ChoiceField(choices=[("import", "Import"), ("replay", "Replay"), ("follow", "Follow")])
    file = forms.CharField(max_length=512)
    speed = forms.FloatField(min_value=0, max_value=1000, required=False, initial=0)
    duration = forms.FloatField(min_value=5, max_value=86400, required=False, initial=60)


class TriageForm(forms.Form):
    to_status = forms.ChoiceField(choices=WorkflowStatus.choices, label="Trạng thái")
    to_assessment = forms.ChoiceField(choices=Assessment.choices, label="Đánh giá")
    note = forms.CharField(
        widget=forms.Textarea(attrs={"rows": 3}), required=False, max_length=4000, label="Ghi chú"
    )


class SuppressionForm(forms.Form):
    scope = forms.ChoiceField(
        choices=[("entity", "Entity này"), ("rule", "Rule trên entity này")], label="Phạm vi"
    )
    rule_id = forms.CharField(max_length=16, required=False)
    days = forms.IntegerField(min_value=1, max_value=30, initial=7, label="Hết hạn sau (ngày)")
    reason = forms.CharField(max_length=500, min_length=10, label="Lý do")


class ReasonForm(forms.Form):
    reason = forms.CharField(max_length=500, min_length=5, label="Lý do (audit)")


class ThresholdForm(ReasonForm):
    threshold = forms.FloatField(min_value=0.0001, max_value=1.0)


class SyntheticForm(forms.Form):
    dataset_id = forms.SlugField(max_length=60)
    seed = forms.IntegerField(min_value=0, max_value=2**31, initial=1337)
    captures = forms.IntegerField(min_value=4, max_value=20, initial=10)


class LabForm(forms.Form):
    dataset_id = forms.SlugField(max_length=60)
    profile = forms.ChoiceField(choices=[("default", "default (~8 phút)"), ("smoke", "smoke (~1 phút)")])


class ExperimentForm(forms.Form):
    exp_id = forms.SlugField(max_length=60)
    window_size = forms.IntegerField(min_value=5, max_value=3600, initial=300)
    lateness = forms.IntegerField(min_value=0, max_value=3600, initial=60)
    counts = forms.CharField(max_length=20, required=False, help_text="train,val,test, ví dụ 5,2,3")
    http_feature_set = forms.ChoiceField(
        choices=[
            ("http_v1", "http_v1 (đủ status/bytes/duration)"),
            ("http_v1_core", "http_v1_core (log không có duration, vd. combined)"),
        ],
        initial="http_v1",
        label="Feature set HTTP",
    )

    def clean_counts(self):
        v = self.cleaned_data["counts"].strip()
        if not v:
            return None
        try:
            parts = [int(x) for x in v.split(",")]
        except ValueError:
            raise forms.ValidationError("dạng a,b,c") from None
        if len(parts) != 3 or min(parts) < 1:
            raise forms.ValidationError("cần 3 số >= 1")
        return parts


class RuleEditForm(forms.Form):
    definition = forms.CharField(
        widget=forms.Textarea(attrs={"rows": 18, "spellcheck": "false"}), max_length=8000
    )
    enabled = forms.BooleanField(required=False)
    reason = forms.CharField(max_length=500, min_length=5)


class ReportForm(forms.Form):
    kind = forms.ChoiceField(choices=[("alerts", "Alerts"), ("experiment", "Experiment")])
    experiment = forms.SlugField(max_length=64, required=False)
    namespace = forms.CharField(max_length=100, initial="live")
    days = forms.IntegerField(min_value=1, max_value=365, initial=30)
    public_draft = forms.BooleanField(required=False)
