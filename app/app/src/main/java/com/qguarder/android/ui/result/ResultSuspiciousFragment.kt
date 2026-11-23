package com.qguarder.android.ui.result

import android.animation.ObjectAnimator
import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.view.animation.DecelerateInterpolator
import android.view.animation.OvershootInterpolator
import android.widget.LinearLayout
import android.widget.TextView
import androidx.core.widget.NestedScrollView
import androidx.fragment.app.Fragment
import androidx.fragment.app.viewModels
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.lifecycleScope
import androidx.lifecycle.repeatOnLifecycle
import androidx.navigation.fragment.findNavController
import androidx.navigation.fragment.navArgs
import com.google.android.material.button.MaterialButton
import com.google.android.material.dialog.MaterialAlertDialogBuilder
import com.qguarder.android.R
import com.qguarder.android.data.ScanResultStore
import com.qguarder.android.data.local.CustomTabsHelper
import com.qguarder.android.databinding.FragmentResultSuspiciousBinding
import com.qguarder.android.domain.model.RiskLevel
import com.qguarder.android.domain.model.XaiItem
import dagger.hilt.android.AndroidEntryPoint
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import javax.inject.Inject

@AndroidEntryPoint
class ResultSuspiciousFragment : Fragment() {

    private var _binding: FragmentResultSuspiciousBinding? = null
    private val binding get() = _binding!!

    private val viewModel: ResultViewModel by viewModels()
    private val args: ResultSuspiciousFragmentArgs by navArgs()

    @Inject lateinit var scanResultStore: ScanResultStore

    override fun onCreateView(
        inflater: LayoutInflater, container: ViewGroup?, savedInstanceState: Bundle?
    ): View {
        _binding = FragmentResultSuspiciousBinding.inflate(inflater, container, false)
        return binding.root
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)

        val url = args.url.ifEmpty { scanResultStore.latestSuspicious?.url ?: "" }

        binding.tvUrl.text = url

        scanResultStore.latestSuspicious?.let { result ->
            bindAnalysisResult(result.finalScore, result.vtTotalEngines, result.vtDetectedEngines)
            if (result.xaiFeatures.isNotEmpty()) {
                bindDetectionReasons(result.xaiFeatures)
                bindXaiFeatures(result.xaiFeatures)
            }
        }

        binding.toolbar.setNavigationOnClickListener {
            findNavController().navigate(R.id.action_result_suspicious_to_scan)
        }

        if (url.isNotEmpty()) viewModel.checkFavorite(url)

        binding.btnFavorite.setOnClickListener {
            viewModel.toggleFavorite(url = url, title = null, riskLevel = "SUSPICIOUS")
        }

        viewLifecycleOwner.lifecycleScope.launch {
            var isFirstEmit = true
            repeatOnLifecycle(Lifecycle.State.STARTED) {
                viewModel.isFavorite.collect { isFavorite ->
                    binding.btnFavorite.setImageResource(
                        if (isFavorite) R.drawable.ic_favorites else R.drawable.ic_star_outline
                    )
                    if (!isFirstEmit) {
                        binding.btnFavorite.animate()
                            .scaleX(1.3f).scaleY(1.3f).setDuration(150)
                            .setInterpolator(OvershootInterpolator(2f))
                            .withEndAction {
                                binding.btnFavorite.animate()
                                    .scaleX(1f).scaleY(1f).setDuration(200).start()
                            }.start()
                    }
                    isFirstEmit = false
                }
            }
        }

        binding.btnBack.setOnClickListener {
            findNavController().navigate(R.id.action_result_suspicious_to_scan)
        }

        binding.btnConnect.setOnClickListener {
            showWarningConfirmDialog(url)
        }

        // 순차 콘텐츠 공개 애니메이션
        playStaggerAnimation()
    }

    private fun playStaggerAnimation() {
        val scrollView = binding.root.getChildAt(1) as? NestedScrollView ?: return
        val container = scrollView.getChildAt(0) as? LinearLayout ?: return
        val decelerate = DecelerateInterpolator(1.5f)
        val offsetPx = 28f * resources.displayMetrics.density

        for (i in 0 until container.childCount) {
            val child = container.getChildAt(i)
            if (child.visibility == View.GONE) continue
            child.alpha = 0f
            child.translationY = offsetPx
            child.animate()
                .alpha(1f).translationY(0f)
                .setDuration(320).setStartDelay((i * 60).toLong())
                .setInterpolator(decelerate).start()
        }
    }

    private fun showWarningConfirmDialog(url: String) {
        val dialogView = LayoutInflater.from(requireContext())
            .inflate(R.layout.dialog_suspicious_confirm, null)

        val dialog = MaterialAlertDialogBuilder(requireContext())
            .setView(dialogView)
            .create()

        // X 닫기 버튼
        dialogView.findViewById<TextView>(R.id.btn_close)
            .setOnClickListener { dialog.dismiss() }

        dialogView.findViewById<MaterialButton>(R.id.btn_stay_safe)
            .setOnClickListener {
                dialog.dismiss()
                findNavController().navigate(R.id.action_result_suspicious_to_scan)
            }

        val btnProceed = dialogView.findViewById<MaterialButton>(R.id.btn_proceed)

        // 3초 카운트다운 후 접속 버튼 활성화 (충동 클릭 방지)
        val countdownJob = viewLifecycleOwner.lifecycleScope.launch {
            for (i in 3 downTo 1) {
                btnProceed.text = "${i}초 후 활성화"
                delay(1000)
            }
            btnProceed.isEnabled = true
            btnProceed.text = "위험 감수하고 접속"
            // 활성화 어텐션 펄스
            btnProceed.animate().scaleX(1.05f).scaleY(1.05f).setDuration(200)
                .withEndAction {
                    btnProceed.animate().scaleX(1f).scaleY(1f).setDuration(200).start()
                }.start()
        }

        btnProceed.setOnClickListener {
            dialog.dismiss()
            viewModel.recordVisit(url, RiskLevel.SUSPICIOUS)
            CustomTabsHelper.open(requireContext(), url)
        }

        dialog.setOnDismissListener { countdownJob.cancel() }
        dialog.show()
    }

    private fun bindAnalysisResult(finalScore: Int, vtTotal: Int, vtDetected: Int) {
        // finalScore: 0~100 정수
        binding.tvScore.text = when {
            finalScore < 55 -> "보통 ($finalScore%)"
            finalScore < 65 -> "높음 ($finalScore%)"
            else            -> "매우 높음 ($finalScore%)"
        }

        // 악성 탐지 0건은 안전 보장이 아니라 '탐지 근거 없음'이므로 중립색 표시
        if (vtTotal > 0) {
            binding.tvVt.text = "$vtDetected / $vtTotal 엔진 악성 탐지"
            binding.tvVt.setTextColor(
                if (vtDetected == 0) 0xFF757575.toInt() else 0xFFFF8F00.toInt()
            )
        } else {
            // 미등재·API 장애 등으로 VT 정보를 얻지 못한 경우
            binding.tvVt.text = "VT 정보 없음"
            binding.tvVt.setTextColor(0xFF757575.toInt())
        }
    }

    private fun bindDetectionReasons(features: List<XaiItem>) {
        val container = binding.llDetectionReasons
        container.removeAllViews()

        // 서버 제공 한글 title/description을 그대로 표시
        features.take(3).forEach { item ->
            val tv = TextView(requireContext()).apply {
                text = "• ${item.title}"
                textSize = 12f
                setTextColor(0xFFFF8F00.toInt())
                setPadding(0, 0, 0, 12)
            }
            container.addView(tv)
        }

        if (container.childCount == 0) {
            val tv = TextView(requireContext()).apply {
                text = "• ML 엔진 의심 패턴 감지"
                textSize = 12f
                setTextColor(0xFFFF8F00.toInt())
            }
            container.addView(tv)
        }
    }

    private fun bindXaiFeatures(features: List<XaiItem>) {
        binding.cardXai.visibility     = View.VISIBLE
        binding.spacerNoXai.visibility = View.GONE

        val container = binding.llXaiFeatures
        container.removeAllViews()
        var xaiAnimIndex = 0

        features.take(5).forEach { item ->
            val row = LayoutInflater.from(requireContext())
                .inflate(R.layout.item_xai_row, container, false)

            // 서버 제공 한글 피처명 그대로 표시
            row.findViewById<TextView>(R.id.tv_label).text = item.title

            // 기여도(0~100 정수) 프로그레스 표시 + 채움 애니메이션
            val bar = row.findViewById<android.widget.ProgressBar>(R.id.progress_xai)
            val target = item.contribution.coerceIn(0, 100)
            bar.progress = 0
            ObjectAnimator.ofInt(bar, "progress", 0, target).apply {
                duration = 600
                startDelay = (xaiAnimIndex * 100).toLong()
                interpolator = DecelerateInterpolator(2f)
                start()
            }
            xaiAnimIndex++
            // severity에 따른 색상
            val barColor = when (item.severity) {
                "high"   -> 0xFFFF8F00.toInt()   // 주황
                "medium" -> 0xFFD97706.toInt()   // 앰버
                else     -> 0xFF1D9E75.toInt()   // 녹색
            }
            bar.progressTintList = android.content.res.ColorStateList.valueOf(barColor)

            val scoreView = row.findViewById<TextView>(R.id.tv_score)
            scoreView.text = "${item.contribution}%"
            scoreView.setTextColor(barColor)

            container.addView(row)
        }
    }

    override fun onDestroyView() {
        super.onDestroyView()
        _binding = null
    }
}
