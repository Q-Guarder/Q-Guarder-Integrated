package com.qguarder.android.ui.logs

import android.graphics.drawable.GradientDrawable
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import androidx.recyclerview.widget.DiffUtil
import androidx.recyclerview.widget.ListAdapter
import androidx.recyclerview.widget.RecyclerView
import com.qguarder.android.R
import com.qguarder.android.data.remote.dto.ScanLogItemDto
import com.qguarder.android.domain.model.RiskLevel
import com.qguarder.android.databinding.ItemLogBinding
import com.qguarder.android.databinding.ItemVisitLogBinding
import java.time.OffsetDateTime
import java.time.ZoneId
import java.time.format.DateTimeFormatter
import java.util.Locale

/**
 * 로그 탭 통합 어댑터 — 스캔 로그 / 방문 기록 두 ViewType 지원.
 *
 * VIEW_TYPE_SCAN  → item_log.xml      (ItemLogBinding)
 * VIEW_TYPE_VISIT → item_visit_log.xml (ItemVisitLogBinding)
 */
class LogsAdapter(
    private val onItemClick:  (LogListItem)    -> Unit,
    private val onReportClick: (ScanLogItemDto) -> Unit,
) : ListAdapter<LogListItem, RecyclerView.ViewHolder>(DiffCallback) {

    // ── ViewType ────────────────────────────────────────────────────

    companion object {
        private const val VIEW_TYPE_SCAN  = 0
        private const val VIEW_TYPE_VISIT = 1

        private val DiffCallback = object : DiffUtil.ItemCallback<LogListItem>() {
            override fun areItemsTheSame(old: LogListItem, new: LogListItem): Boolean =
                when {
                    old is LogListItem.ScanLog  && new is LogListItem.ScanLog  ->
                        old.dto.scanId == new.dto.scanId
                    old is LogListItem.VisitLog && new is LogListItem.VisitLog ->
                        old.url == new.url && old.visitedAt == new.visitedAt
                    else -> false
                }
            override fun areContentsTheSame(old: LogListItem, new: LogListItem): Boolean =
                old == new
        }

        private fun formatTime(ts: String): String = try {
            val odt   = OffsetDateTime.parse(ts)
            val local = odt.atZoneSameInstant(ZoneId.systemDefault())
            DateTimeFormatter.ofPattern("a hh:mm", Locale.KOREA).format(local)
        } catch (_: Exception) { ts }
    }

    override fun getItemViewType(position: Int) = when (getItem(position)) {
        is LogListItem.ScanLog  -> VIEW_TYPE_SCAN
        is LogListItem.VisitLog -> VIEW_TYPE_VISIT
    }

    // ── ViewHolder 생성 ──────────────────────────────────────────────

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): RecyclerView.ViewHolder {
        val inflater = LayoutInflater.from(parent.context)
        return when (viewType) {
            VIEW_TYPE_SCAN  -> ScanViewHolder(ItemLogBinding.inflate(inflater, parent, false))
            else            -> VisitViewHolder(ItemVisitLogBinding.inflate(inflater, parent, false))
        }
    }

    override fun onBindViewHolder(holder: RecyclerView.ViewHolder, position: Int) {
        when (val item = getItem(position)) {
            is LogListItem.ScanLog  -> (holder as ScanViewHolder).bind(item.dto)
            is LogListItem.VisitLog -> (holder as VisitViewHolder).bind(item)
        }
    }

    // ── ScanViewHolder ───────────────────────────────────────────────

    inner class ScanViewHolder(private val binding: ItemLogBinding) :
        RecyclerView.ViewHolder(binding.root) {

        fun bind(item: ScanLogItemDto) {
            binding.root.setOnClickListener { onItemClick(LogListItem.ScanLog(item)) }
            when (item.riskLevel) {
                "BLOCKED" -> {
                    binding.tvTitle.text = RiskLevel.labelOf("BLOCKED")
                    binding.tvTitle.setTextColor(0xFFE53935.toInt())
                    binding.iconBg.setBackgroundResource(R.drawable.bg_circle_red)
                    binding.ivLogIcon.setImageResource(R.drawable.ic_warning)
                    binding.tvReportTag.visibility = View.GONE
                }
                "SECURED" -> {
                    binding.tvTitle.text = RiskLevel.labelOf("SECURED")
                    binding.tvTitle.setTextColor(0xFF3D5AFE.toInt())
                    binding.iconBg.setBackgroundResource(R.drawable.bg_circle_blue)
                    binding.ivLogIcon.setImageResource(R.drawable.ic_shield)
                    binding.tvReportTag.visibility = View.VISIBLE
                    binding.tvReportTag.setOnClickListener { onReportClick(item) }
                }
                "SUSPICIOUS" -> {
                    binding.tvTitle.text = RiskLevel.labelOf("SUSPICIOUS")
                    binding.tvTitle.setTextColor(0xFFD97706.toInt())
                    binding.iconBg.setBackgroundResource(R.drawable.bg_circle_amber)
                    binding.ivLogIcon.setImageResource(R.drawable.ic_shield)
                    binding.tvReportTag.visibility = View.GONE
                }
                "REPORTED" -> {
                    binding.tvTitle.text = "신고됨"
                    binding.tvTitle.setTextColor(0xFF888888.toInt())
                    binding.iconBg.setBackgroundResource(R.drawable.bg_circle_gray)
                    binding.ivLogIcon.setImageResource(R.drawable.ic_warning)
                    binding.tvReportTag.visibility = View.GONE
                }
                else -> {
                    binding.tvTitle.text = RiskLevel.labelOf(item.riskLevel)
                    binding.tvTitle.setTextColor(0xFF888888.toInt())
                    binding.iconBg.setBackgroundResource(R.drawable.bg_circle_gray)
                    binding.ivLogIcon.setImageResource(R.drawable.ic_shield)
                    binding.tvReportTag.visibility = View.GONE
                }
            }
            binding.tvUrl.text  = item.url
            binding.tvTime.text = formatTime(item.scannedAt)

            // 위험도 점수 배지 — 판정 임계값 τ_L=0.45, τ_H=0.65와 일치
            // (0-44: 녹색 SECURED, 45-64: 주황 SUSPICIOUS, 65-100: 빨강 BLOCKED)
            if (item.finalScore > 0) {
                binding.tvScore.visibility = View.VISIBLE
                binding.tvScore.text = "${item.finalScore}점"
                val badgeColor = when {
                    item.finalScore < 45 -> 0xFF1D9E75.toInt()
                    item.finalScore < 65 -> 0xFFD97706.toInt()
                    else                 -> 0xFFE53935.toInt()
                }
                binding.tvScore.background = GradientDrawable().apply {
                    shape = GradientDrawable.RECTANGLE
                    cornerRadius = 8f
                    setColor(badgeColor)
                }
            } else {
                binding.tvScore.visibility = View.GONE
            }
        }
    }

    // ── VisitViewHolder ──────────────────────────────────────────────

    inner class VisitViewHolder(private val binding: ItemVisitLogBinding) :
        RecyclerView.ViewHolder(binding.root) {

        fun bind(item: LogListItem.VisitLog) {
            binding.root.setOnClickListener { onItemClick(item) }
            // 방문한 URL의 위험도에 따라 원형 배경 + 텍스트 색상 + 한글 레이블 결정
            val (color, circleBg) = when (item.riskLevel) {
                "BLOCKED"    -> 0xFFE53935.toInt() to R.drawable.bg_circle_red
                "SUSPICIOUS" -> 0xFFD97706.toInt() to R.drawable.bg_circle_amber
                else         -> 0xFF1D9E75.toInt() to R.drawable.bg_circle_green
            }

            binding.iconBgVisit.setBackgroundResource(circleBg)
            binding.tvVisitRisk.text      = RiskLevel.labelOf(item.riskLevel)
            binding.tvVisitRisk.setTextColor(color)
            binding.tvVisitUrl.text       = item.url
            binding.tvVisitTime.text      = formatTime(item.visitedAt)
        }
    }
}
