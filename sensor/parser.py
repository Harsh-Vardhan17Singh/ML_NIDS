"""
Defensive log and telemetry stream parser.
Handles Zeek TSV logs, JSON Lines, and CSV flow records without crashing
on malformed rows or corrupted data.
"""

from __future__ import annotations
import csv
import json
import logging
from pathlib import Path
from typing import Generator, Iterable, List, Optional, Set, Tuple, Union, Any, Dict
from .schemas import CanonicalFlow, ParsingSummary, ParsingErrorDetail
from .normalize import normalize_flow_record, normalize_zeek_record

logger = logging.getLogger("sentinelnids.sensor.parser")


class DefensiveLogParser:
    """
    Robust telemetry parser with granular error tracking and defensive failure isolation.
    Guarantees that individual corrupted lines/records are logged and counted without
    halting processing of subsequent valid records.
    """

    def __init__(
        self,
        default_sensor_id: str = "lab-sensor-01",
        deduplicate: bool = True,
        max_errors_retained: int = 200,
    ) -> None:
        self.default_sensor_id = default_sensor_id
        self.deduplicate = deduplicate
        self.max_errors_retained = max_errors_retained
        self._seen_event_ids: Set[str] = set()

    def reset_deduplication(self) -> None:
        """Clear in-memory deduplication state."""
        self._seen_event_ids.clear()

    def parse_file(self, file_path: Union[str, Path]) -> Tuple[List[CanonicalFlow], ParsingSummary]:
        """
        Parses a file automatically detecting format by header/extension.
        Returns a tuple of (list of valid CanonicalFlow objects, ParsingSummary).
        """
        path = Path(file_path)
        if not path.is_file():
            summary = ParsingSummary(
                total_records=0,
                accepted_records=0,
                rejected_records=1,
                errors=[
                    ParsingErrorDetail(
                        index=0,
                        error_code="FILE_NOT_FOUND",
                        message=f"File does not exist: {str(path)}"
                    )
                ]
            )
            return [], summary

        with path.open("r", encoding="utf-8", errors="replace") as f:
            lines = f.readlines()

        return self.parse_lines(lines, source_hint=path.suffix.lower())

    def parse_lines(
        self,
        lines: Iterable[str],
        source_hint: Optional[str] = None
    ) -> Tuple[List[CanonicalFlow], ParsingSummary]:
        """Parse raw text lines from JSONL or Zeek TSV log."""
        summary = ParsingSummary()
        valid_flows: List[CanonicalFlow] = []

        # Check if Zeek TSV format (#fields header)
        is_zeek_tsv = False
        zeek_fields: List[str] = []

        line_buffer = list(lines)
        for line in line_buffer:
            sline = line.strip()
            if sline.startswith("#fields"):
                is_zeek_tsv = True
                parts = sline.split("\t")
                if len(parts) > 1:
                    zeek_fields = parts[1:]
                else:
                    zeek_fields = sline.split()[1:]
                break

        if is_zeek_tsv and zeek_fields:
            return self._parse_zeek_tsv(line_buffer, zeek_fields)

        # Standard line-by-line parser (JSONL / generic)
        for idx, line in enumerate(line_buffer, start=1):
            sline = line.strip()
            if not sline or sline.startswith("#"):
                continue

            summary.total_records += 1

            # Try JSON parsing
            try:
                record = json.loads(sline)
                if not isinstance(record, dict):
                    self._record_error(summary, idx, "INVALID_FORMAT", "Expected JSON object/dict", sline)
                    continue
            except json.JSONDecodeError as err:
                self._record_error(summary, idx, "MALFORMED_JSON", f"JSON decode failure: {err}", sline)
                continue

            # Normalize to CanonicalFlow
            try:
                flow = normalize_flow_record(record, default_sensor_id=self.default_sensor_id)
            except Exception as err:
                self._record_error(summary, idx, "NORMALIZATION_ERROR", str(err), sline)
                continue

            # Idempotency / Deduplication check
            if self.deduplicate:
                if flow.event_id in self._seen_event_ids:
                    summary.duplicate_records += 1
                    continue
                self._seen_event_ids.add(flow.event_id)

            summary.accepted_records += 1
            valid_flows.append(flow)

        return valid_flows, summary

    def _parse_zeek_tsv(
        self,
        lines: List[str],
        fields: List[str]
    ) -> Tuple[List[CanonicalFlow], ParsingSummary]:
        """Internal parser for Zeek tab-delimited conn.log files."""
        summary = ParsingSummary()
        valid_flows: List[CanonicalFlow] = []

        for idx, line in enumerate(lines, start=1):
            sline = line.strip()
            if not sline or sline.startswith("#"):
                continue

            summary.total_records += 1
            parts = sline.split("\t")
            if len(parts) != len(fields):
                # Try space-delimited as fallback
                parts = sline.split()
                if len(parts) != len(fields):
                    self._record_error(
                        summary, idx, "ZEEK_COLUMN_MISMATCH",
                        f"Expected {len(fields)} fields, got {len(parts)}", sline
                    )
                    continue

            record_dict = dict(zip(fields, parts))

            try:
                flow = normalize_zeek_record(record_dict, default_sensor_id=self.default_sensor_id)
            except Exception as err:
                self._record_error(summary, idx, "ZEEK_NORMALIZATION_ERROR", str(err), sline)
                continue

            if self.deduplicate:
                if flow.event_id in self._seen_event_ids:
                    summary.duplicate_records += 1
                    continue
                self._seen_event_ids.add(flow.event_id)

            summary.accepted_records += 1
            valid_flows.append(flow)

        return valid_flows, summary

    def parse_dict_batch(
        self,
        records: List[Dict[str, Any]]
    ) -> Tuple[List[CanonicalFlow], ParsingSummary]:
        """Parses a batch of dictionaries (e.g. from an API payload)."""
        summary = ParsingSummary()
        valid_flows: List[CanonicalFlow] = []

        for idx, item in enumerate(records, start=1):
            summary.total_records += 1
            if not isinstance(item, dict):
                self._record_error(summary, idx, "INVALID_RECORD_TYPE", f"Expected dictionary, got {type(item).__name__}")
                continue

            try:
                flow = normalize_flow_record(item, default_sensor_id=self.default_sensor_id)
            except Exception as err:
                self._record_error(summary, idx, "VALIDATION_FAILED", str(err))
                continue

            if self.deduplicate:
                if flow.event_id in self._seen_event_ids:
                    summary.duplicate_records += 1
                    continue
                self._seen_event_ids.add(flow.event_id)

            summary.accepted_records += 1
            valid_flows.append(flow)

        return valid_flows, summary

    def _record_error(
        self,
        summary: ParsingSummary,
        index: int,
        code: str,
        message: str,
        raw_preview: Optional[str] = None
    ) -> None:
        summary.rejected_records += 1
        if len(summary.errors) < self.max_errors_retained:
            preview = (raw_preview[:120] + "...") if raw_preview and len(raw_preview) > 120 else raw_preview
            summary.errors.append(
                ParsingErrorDetail(
                    index=index,
                    error_code=code,
                    message=message,
                    raw_preview=preview
                )
            )
