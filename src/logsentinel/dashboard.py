"""Streamlit dashboard for LogSentinel security investigations."""

import json
import tempfile
from pathlib import Path

import pandas as pd
import streamlit as st

from logsentinel.reporting import generate_investigation_report

st.set_page_config(
    page_title="LogSentinel | Security Dashboard",
    page_icon="🛡️",
    layout="wide",
)

st.title("🛡️ LogSentinel")
st.caption("Security Log Analysis & Threat Detection Platform")

with st.sidebar:
    st.header("Investigation")
    uploaded_file = st.file_uploader(
        "Upload a security log",
        type=["log", "txt"],
        help="Upload a UTF-8 pipe-delimited security log file.",
    )
    top_ip_limit = st.slider(
        "Top source IPs",
        min_value=1,
        max_value=20,
        value=5,
    )
    st.divider()
    st.caption("Analysis uses LogSentinel's deterministic detection rules.")

if uploaded_file is None:
    st.info("Upload a security log in the sidebar to begin an investigation.")
    sample_path = Path("examples/sample_security.log")

    if sample_path.exists():
        if st.button("Analyze bundled sample log", type="primary"):
            st.session_state["analyze_sample"] = True

    if not st.session_state.get("analyze_sample", False):
        st.stop()

    log_bytes = sample_path.read_bytes()
    source_name = sample_path.name
else:
    log_bytes = uploaded_file.getvalue()
    source_name = uploaded_file.name
    st.session_state["analyze_sample"] = False

if not log_bytes:
    st.error("The selected log file is empty.")
    st.stop()

try:
    # Use a temporary file so the existing ingestion and reporting pipeline
    # can process uploaded data without changing the core application.
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_path = Path(temp_dir) / source_name
        temp_path.write_bytes(log_bytes)
        report = generate_investigation_report(
            temp_path,
            top_ip_limit=top_ip_limit,
        )
except (OSError, UnicodeError, ValueError) as exc:
    st.error(f"Unable to analyze this file: {exc}")
    st.stop()

summary = report["summary"]
findings = report["findings"]
events = report["events"]
parse_errors = report["parse_errors"]

st.subheader("Investigation Overview")
st.caption(f"Source file: {source_name}")

metric_columns = st.columns(4)
metric_columns[0].metric("Events Analyzed", summary["total_events"])
metric_columns[1].metric("Security Findings", summary["total_findings"])
metric_columns[2].metric("Unique Source IPs", summary["unique_source_ips"])
metric_columns[3].metric("Malformed Lines", len(parse_errors))

if findings:
    st.warning(f"{len(findings)} finding(s) matched the configured detection rules.")
else:
    st.success("No findings matched the configured detection rules.")

st.divider()
st.subheader("Security Analytics")

left_chart, right_chart = st.columns(2)

with left_chart:
    st.markdown("**Events by Type**")
    events_by_type = summary["events_by_type"]
    if events_by_type:
        event_chart = pd.DataFrame(
            {
                "Event Type": list(events_by_type.keys()),
                "Count": list(events_by_type.values()),
            }
        ).set_index("Event Type")
        st.bar_chart(event_chart)
    else:
        st.info("No valid events to chart.")

with right_chart:
    st.markdown("**Top Source IPs**")
    top_ips = summary["top_source_ips"]
    if top_ips:
        ip_chart = pd.DataFrame(top_ips).set_index("source_ip")
        st.bar_chart(ip_chart)
    else:
        st.info("No source IP data available.")

st.divider()
st.subheader("Detection Findings")

if findings:
    findings_df = pd.DataFrame(findings)
    st.dataframe(
        findings_df,
        use_container_width=True,
        hide_index=True,
    )
else:
    st.info("No detection findings to display.")

st.subheader("Security Events")

if events:
    events_df = pd.DataFrame(events)
    search_text = st.text_input(
        "Filter events",
        placeholder="Search username, source IP, event type, or message",
    )

    if search_text.strip():
        searchable_columns = [
            "timestamp",
            "source",
            "event_type",
            "username",
            "source_ip",
            "status",
            "message",
            "severity",
        ]
        mask = (
            events_df[searchable_columns]
            .astype(str)
            .apply(
                lambda column: column.str.contains(
                    search_text,
                    case=False,
                    regex=False,
                )
            )
            .any(axis=1)
        )
        events_df = events_df[mask]

    st.dataframe(
        events_df,
        use_container_width=True,
        hide_index=True,
    )
    st.caption(f"{len(events_df)} event(s) shown.")
else:
    st.info("No valid security events were parsed.")

if parse_errors:
    with st.expander("Inspect malformed log lines"):
        st.dataframe(
            pd.DataFrame(parse_errors),
            use_container_width=True,
            hide_index=True,
        )

st.divider()
st.subheader("Export Investigation Report")

report_json = json.dumps(report, indent=2, ensure_ascii=False)
st.download_button(
    label="Download JSON Report",
    data=report_json,
    file_name="logsentinel_investigation_report.json",
    mime="application/json",
    type="primary",
)

st.caption(
    "LogSentinel is a rule-based analysis tool. Findings should be "
    "reviewed by a security analyst before taking action."
)
