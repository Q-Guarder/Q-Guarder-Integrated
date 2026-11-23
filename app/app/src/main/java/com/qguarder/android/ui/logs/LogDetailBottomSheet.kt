package com.qguarder.android.ui.logs

import android.graphics.drawable.GradientDrawable
import android.os.Bundle
import android.util.TypedValue
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.LinearLayout
import android.widget.TextView
import androidx.fragment.app.FragmentManager
import com.google.android.material.bottomsheet.BottomSheetDialogFragment
import com.qguarder.android.R
import com.qguarder.android.data.remote.dto.ScanLogItemDto
import com.qguarder.android.domain.model.RiskLevel
import com.qguarder.android.databinding.BottomSheetLogDetailBinding
import java.time.OffsetDateTime
import java.time.ZoneId
import java.time.format.DateTimeFormatter
import java.util.Locale

/**
 * 로그 항목 터치 시 나타나는 URL 상세 바텀시트.
 *
 * - 스캔 기록: 해당 URL의 모든 스캔 결과를 최신순으로 표시
 * - 방문 기록: 해당 URL로 실제 이동한 기록을 최신순으로 표시
 *
 * 데이터 전달: companion object의 [payload]에 임시 보관 후 [show]에서 주입.
 * (ScanLogItemDto / VisitLog 가 Parcelable이 아니므로 인메모리 홀더 패턴 사용)
 */
class LogDetailBottomSheet : BottomSheetDialogFragment() {

    private var _binding: BottomSheetLogDetailBinding? = null
    private val binding get() = _binding!!

    override fun onCreateView(
        inflater: LayoutInflater, container: ViewGroup?, savedInstanceState: Bundle?
    ): View {
        _binding = BottomSheetLogDetailBinding.inflate(inflater, container, false)
        return binding.root
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)

        val data = payload ?: run { dismiss(); return }
        payload  = null   // 소비 후 즉시 해제

        bindHeader(data)
        bindScanSection(data.scans)
        bindVisitSection(data.visits)
    }

    // ── 헤더: URL + 위험도 배지 ──────────────────────────────────────

    private fun bindHeader(data: Payload) {
        binding.tvDetailUrl.text = data.url

        val (label, color) = riskStyle(data.clickedRiskLevel)
        binding.tvDetailRisk.text = label
        binding.tvDetailRisk.background = roundedBadge(color)
    }

    // ── 스캔 기록 섹션 ───────────────────────────────────────────────

    private fun bindScanSection(scans: List<ScanLogItemDto>) {
        binding.tvScanCount.text = "${scans.size}건"

        if (scans.isEmpty()) {
            addEmptyRow(binding.llScanList, "스캔 기록 없음")
            return
        }
        scans.forEach { scan ->
            val (label, color) = riskStyle(scan.riskLevel)
            addRow(binding.llScanList, label, color, formatDateTime(scan.scannedAt), scan.finalScore)
        }
    }

    // ── 방문 기록 섹션 ───────────────────────────────────────────────

    private fun bindVisitSection(visits: List<LogListItem.VisitLog>) {
        binding.tvVisitCount.text = "${visits.size}건"

        if (visits.isEmpty()) {
            addEmptyRow(binding.llVisitList, "이 URL을 직접 방문한 기록이 없습니다")
            return
        }
        visits.forEach { visit ->
            val (_, color) = riskStyle(visit.riskLevel)
            addRow(binding.llVisitList, "방문", 0xFF1D9E75.toInt(), formatDateTime(visit.visitedAt))
        }
    }

    // ── 뷰 헬퍼 ─────────────────────────────────────────────────────

    /** 스캔/방문 행 하나를 동적으로 추가한다 */
    private fun addRow(container: LinearLayout, label: String, dotColor: Int, time: String, score: Int = 0) {
        val row = LayoutInflater.from(requireContext())
            .inflate(R.layout.item_detail_row, container, false)

        // 색상 점 — oval GradientDrawable
        row.findViewById<View>(R.id.view_dot).background = GradientDrawable().apply {
            shape = GradientDrawable.OVAL
            setColor(dotColor)
        }

        row.findViewById<TextView>(R.id.tv_row_label).apply {
            text = label
            setTextColor(dotColor)
        }

        // 위험도 점수 배지 — 판정 임계값 τ_L=0.45, τ_H=0.65와 일치 (0-44 녹색, 45-64 주황, 65-100 빨강)
        val scoreTv = row.findViewById<TextView>(R.id.tv_row_score)
        if (score > 0) {
            scoreTv.visibility = View.VISIBLE
            scoreTv.text = "${score}점"
            val badgeColor = when {
                score < 45 -> 0xFF1D9E75.toInt()
                score < 65 -> 0xFFD97706.toInt()
                else       -> 0xFFE53935.toInt()
            }
            scoreTv.background = GradientDrawable().apply {
                shape = GradientDrawable.RECTANGLE
                cornerRadius = 6f.dpToPx()
                setColor(badgeColor)
            }
        }

        row.findViewById<TextView>(R.id.tv_row_time).text = time

        container.addView(row)
    }

    /** 데이터가 없을 때 안내 텍스트 행 추가 */
    private fun addEmptyRow(container: LinearLayout, message: String) {
        val tv = TextView(requireContext()).apply {
            text      = message
            textSize  = 12f
            setTextColor(
                TypedValue().let {
                    requireContext().theme.resolveAttribute(
                        android.R.attr.textColorSecondary, it, true
                    )
                    it.data
                }
            )
        }
        container.addView(tv)
    }

    // ── 공통 유틸 ────────────────────────────────────────────────────

    /** 위험도 문자열 → (한글 레이블, 색상) */
    private fun riskStyle(riskLevel: String): Pair<String, Int> = when (riskLevel) {
        "BLOCKED"    -> RiskLevel.labelOf("BLOCKED")    to 0xFFE53935.toInt()
        "SUSPICIOUS" -> RiskLevel.labelOf("SUSPICIOUS") to 0xFFD97706.toInt()
        "REPORTED"   -> "신고됨"                          to 0xFF888888.toInt()
        else         -> RiskLevel.labelOf("SECURED")    to 0xFF1D9E75.toInt()
    }

    /** 위험도 배지 배경 (흰 텍스트를 위한 불투명 컬러 배경) */
    private fun roundedBadge(color: Int) = GradientDrawable().apply {
        shape = GradientDrawable.RECTANGLE
        cornerRadius = 6f.dpToPx()
        setColor(color)
    }

    private fun Float.dpToPx(): Float =
        TypedValue.applyDimension(TypedValue.COMPLEX_UNIT_DIP, this, resources.displayMetrics)

    /** ISO 8601 → "2025.05.12  오전 09:30" */
    private fun formatDateTime(ts: String): String = try {
        val odt   = OffsetDateTime.parse(ts)
        val local = odt.atZoneSameInstant(ZoneId.systemDefault())
        DateTimeFormatter.ofPattern("yyyy.MM.dd  a hh:mm", Locale.KOREA).format(local)
    } catch (_: Exception) { ts }

    override fun onDestroyView() {
        super.onDestroyView()
        _binding = null
    }

    // ── 데이터 전달 ──────────────────────────────────────────────────

    /**
     * ScanLogItemDto / VisitLog 는 Parcelable이 아니므로
     * companion object 인메모리 홀더에 임시 보관 후 onViewCreated에서 소비한다.
     */
    private data class Payload(
        val url:              String,
        val clickedRiskLevel: String,
        val scans:            List<ScanLogItemDto>,
        val visits:           List<LogListItem.VisitLog>,
    )

    companion object {
        private var payload: Payload? = null

        /**
         * @param url              선택된 항목의 URL
         * @param clickedRiskLevel 선택된 항목의 위험도 (헤더 배지에 표시)
         * @param scans            동일 URL의 스캔 기록 목록 (최신순)
         * @param visits           동일 URL의 방문 기록 목록 (최신순)
         */
        fun show(
            manager:          FragmentManager,
            url:              String,
            clickedRiskLevel: String,
            scans:            List<ScanLogItemDto>,
            visits:           List<LogListItem.VisitLog>,
        ) {
            payload = Payload(url, clickedRiskLevel, scans, visits)
            LogDetailBottomSheet().show(manager, TAG)
        }

        private const val TAG = "LogDetailBottomSheet"
    }
}
