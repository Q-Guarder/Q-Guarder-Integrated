package com.qguarder.android.ui.logs

import android.animation.ValueAnimator
import android.graphics.Typeface
import kotlin.math.roundToInt
import android.os.Bundle
import android.text.SpannableString
import android.text.Spanned
import android.text.style.ForegroundColorSpan
import android.text.style.StyleSpan
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.view.animation.AnimationUtils
import android.view.animation.DecelerateInterpolator
import android.widget.Toast
import androidx.fragment.app.Fragment
import com.google.android.material.dialog.MaterialAlertDialogBuilder
import com.google.android.material.textfield.TextInputEditText
import com.google.android.material.textfield.TextInputLayout
import androidx.fragment.app.viewModels
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.lifecycleScope
import androidx.lifecycle.repeatOnLifecycle
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import com.qguarder.android.R
import com.qguarder.android.databinding.FragmentLogsBinding
import dagger.hilt.android.AndroidEntryPoint
import kotlinx.coroutines.launch

@AndroidEntryPoint
class LogsFragment : Fragment() {

    private var _binding: FragmentLogsBinding? = null
    private val binding get() = _binding!!
    private val viewModel: LogsViewModel by viewModels()
    private var hasAnimatedList = false
    private var percentAnimator: ValueAnimator? = null

    private val logsAdapter by lazy {
        LogsAdapter(
            onItemClick = { clicked ->
                // 클릭된 항목의 URL과 동일한 모든 스캔/방문 기록을 현재 목록에서 필터링
                val url = when (clicked) {
                    is LogListItem.ScanLog  -> clicked.dto.url
                    is LogListItem.VisitLog -> clicked.url
                }
                val clickedRisk = when (clicked) {
                    is LogListItem.ScanLog  -> clicked.dto.riskLevel
                    is LogListItem.VisitLog -> clicked.riskLevel
                }
                val all    = viewModel.logItems.value
                val scans  = all.filterIsInstance<LogListItem.ScanLog>()
                    .filter { it.dto.url == url }
                    .map { it.dto }
                val visits = all.filterIsInstance<LogListItem.VisitLog>()
                    .filter { it.url == url }

                LogDetailBottomSheet.show(
                    manager          = parentFragmentManager,
                    url              = url,
                    clickedRiskLevel = clickedRisk,
                    scans            = scans,
                    visits           = visits,
                )
            },
            onReportClick = { item ->
                showReportDialog(item)
            }
        )
    }

    override fun onCreateView(
        inflater: LayoutInflater, container: ViewGroup?, savedInstanceState: Bundle?
    ): View {
        _binding = FragmentLogsBinding.inflate(inflater, container, false)
        return binding.root
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)

        val layoutManager = LinearLayoutManager(requireContext())
        binding.rvLogs.adapter = logsAdapter
        binding.rvLogs.layoutManager = layoutManager

        // 무한 스크롤
        binding.rvLogs.addOnScrollListener(object : RecyclerView.OnScrollListener() {
            override fun onScrolled(recyclerView: RecyclerView, dx: Int, dy: Int) {
                if (dy <= 0) return
                val totalItemCount = layoutManager.itemCount
                val lastVisibleItem = layoutManager.findLastVisibleItemPosition()
                if (lastVisibleItem >= totalItemCount - 5) {
                    viewModel.loadMore()
                }
            }
        })

        // 새로고침 버튼
        binding.btnRefresh.setOnClickListener { viewModel.loadLogs() }

        // Pull-to-Refresh
        binding.swipeRefresh.setColorSchemeColors(0xFF3D5AFE.toInt())
        binding.swipeRefresh.setOnRefreshListener { viewModel.loadLogs() }

        // 필터 칩
        binding.chipGroupFilter.setOnCheckedStateChangeListener { _, checkedIds ->
            val filter = when (checkedIds.firstOrNull()) {
                R.id.chip_safe       -> LogFilter.SECURED
                R.id.chip_threat     -> LogFilter.BLOCKED
                R.id.chip_suspicious -> LogFilter.SUSPICIOUS
                else                 -> LogFilter.ALL
            }
            viewModel.setFilter(filter)
        }

        setupObserver()
    }

    private fun setupObserver() {
        viewLifecycleOwner.lifecycleScope.launch {
            viewLifecycleOwner.repeatOnLifecycle(Lifecycle.State.STARTED) {

                launch {
                    viewModel.logItems.collect { list ->
                        logsAdapter.submitList(list)

                        val empty = list.isEmpty()
                        // 빈 상태 크로스페이드 — 먼저 진행 중인 애니메이션 취소해서 withEndAction 경합 방지
                        binding.rvLogs.animate().cancel()
                        binding.layoutEmpty.animate().cancel()

                        if (empty) {
                            binding.rvLogs.animate().alpha(0f).setDuration(250).withEndAction {
                                if (_binding != null) binding.rvLogs.visibility = View.GONE
                            }.start()
                            binding.layoutEmpty.visibility = View.VISIBLE
                            binding.layoutEmpty.alpha = 0f
                            binding.layoutEmpty.animate().alpha(1f).setDuration(250).start()
                        } else {
                            binding.layoutEmpty.animate().alpha(0f).setDuration(250).withEndAction {
                                if (_binding != null) binding.layoutEmpty.visibility = View.GONE
                            }.start()
                            binding.rvLogs.visibility = View.VISIBLE
                            binding.rvLogs.alpha = 1f
                            // 최초 데이터 수신 시 layoutAnimation 적용
                            if (!hasAnimatedList) {
                                hasAnimatedList = true
                                val anim = AnimationUtils.loadLayoutAnimation(
                                    requireContext(), R.anim.layout_animation_fall_down
                                )
                                binding.rvLogs.layoutAnimation = anim
                                binding.rvLogs.scheduleLayoutAnimation()
                            }
                        }
                    }
                }

                launch {
                    viewModel.stats.collect { stats ->
                        if (stats != null) {
                            val safePercent = if (stats.totalScans > 0)
                                (stats.securedCount * 100f / stats.totalScans).roundToInt() else 0
                            val threatCount = stats.blockedCount + stats.reportedCount

                            // 도넛 차트 업데이트 (스위프 애니메이션은 DonutChartView 내장)
                            binding.donutChart.setSafePercent(safePercent)

                            // 퍼센트 텍스트 카운트업 애니메이션
                            percentAnimator?.cancel()
                            percentAnimator = ValueAnimator.ofInt(0, safePercent).apply {
                                duration = 800
                                interpolator = DecelerateInterpolator(2f)
                                addUpdateListener { anim ->
                                    if (_binding != null) {
                                        binding.tvSafePercent.text = "${anim.animatedValue}%"
                                    }
                                }
                                start()
                            }

                            // 통계 요약 (위협 건수 강조)
                            val summaryText = "최근 ${threatCount}건의\n위협으로부터 차단됨"
                            val spannable = SpannableString(summaryText)
                            val numStr = "${threatCount}건"
                            val start = summaryText.indexOf(numStr)
                            if (start >= 0) {
                                spannable.setSpan(
                                    ForegroundColorSpan(0xFFE53935.toInt()),
                                    start, start + numStr.length,
                                    Spanned.SPAN_EXCLUSIVE_EXCLUSIVE
                                )
                                spannable.setSpan(
                                    StyleSpan(Typeface.BOLD),
                                    start, start + numStr.length,
                                    Spanned.SPAN_EXCLUSIVE_EXCLUSIVE
                                )
                            }
                            binding.tvStatsSummary.text = spannable

                            // 레전드 (색상 점) — 안전 / 주의 / 위험 3단계
                            val detailText = "● 안전 ${stats.securedCount}   ● 주의 ${stats.suspiciousCount}   ● 위험 $threatCount"
                            val detailSpan = SpannableString(detailText)
                            // ● 안전 = blue
                            val blueDotIdx = detailText.indexOf('●')
                            detailSpan.setSpan(ForegroundColorSpan(0xFF3D5AFE.toInt()), blueDotIdx, blueDotIdx + 1, Spanned.SPAN_EXCLUSIVE_EXCLUSIVE)
                            // ● 주의 = amber
                            val amberDotIdx = detailText.indexOf('●', blueDotIdx + 1)
                            detailSpan.setSpan(ForegroundColorSpan(0xFFD97706.toInt()), amberDotIdx, amberDotIdx + 1, Spanned.SPAN_EXCLUSIVE_EXCLUSIVE)
                            // ● 위험 = red
                            val redDotIdx = detailText.indexOf('●', amberDotIdx + 1)
                            detailSpan.setSpan(ForegroundColorSpan(0xFFE53935.toInt()), redDotIdx, redDotIdx + 1, Spanned.SPAN_EXCLUSIVE_EXCLUSIVE)
                            binding.tvStatsDetail.text = detailSpan
                        }
                    }
                }

                launch {
                    viewModel.isLoading.collect { loading ->
                        binding.swipeRefresh.isRefreshing = loading
                    }
                }

                launch {
                    viewModel.error.collect { message ->
                        Toast.makeText(requireContext(), message, Toast.LENGTH_SHORT).show()
                    }
                }
            }
        }
    }

    private fun showReportDialog(item: com.qguarder.android.data.remote.dto.ScanLogItemDto) {
        val inputLayout = TextInputLayout(requireContext()).apply {
            hint = "신고 사유를 입력해주세요"
            counterMaxLength = 1000
            isCounterEnabled = true
            setPadding(48, 24, 48, 0)
        }
        val editText = TextInputEditText(requireContext())
        inputLayout.addView(editText)

        val dialog = MaterialAlertDialogBuilder(requireContext())
            .setTitle("신고하기")
            .setMessage("이 URL을 악성으로 신고하시겠어요?\n${item.url}")
            .setView(inputLayout)
            .setPositiveButton("신고", null)  // null로 설정 후 아래서 직접 처리
            .setNegativeButton("취소", null)
            .create()

        dialog.setOnShowListener {
            dialog.getButton(android.app.AlertDialog.BUTTON_POSITIVE).setOnClickListener {
                val reason = editText.text?.toString()?.trim() ?: ""
                if (reason.isEmpty()) {
                    inputLayout.error = "신고 사유를 입력해주세요"
                    return@setOnClickListener
                }
                if (reason.length > 1000) {
                    inputLayout.error = "1000자 이내로 입력해주세요"
                    return@setOnClickListener
                }
                dialog.dismiss()
                viewModel.report(item, reason)
            }
        }
        dialog.show()
    }

    override fun onDestroyView() {
        super.onDestroyView()
        percentAnimator?.cancel()
        _binding = null
    }
}