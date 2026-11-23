package com.qguarder.android.ui.result

import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.view.animation.DecelerateInterpolator
import android.view.animation.OvershootInterpolator
import android.widget.LinearLayout
import androidx.core.widget.NestedScrollView
import androidx.fragment.app.Fragment
import androidx.fragment.app.viewModels
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.lifecycleScope
import androidx.lifecycle.repeatOnLifecycle
import androidx.navigation.fragment.findNavController
import androidx.navigation.fragment.navArgs
import com.qguarder.android.R
import com.qguarder.android.data.local.CustomTabsHelper
import com.qguarder.android.databinding.FragmentResultWhitelistBinding
import com.qguarder.android.domain.model.RiskLevel
import dagger.hilt.android.AndroidEntryPoint
import kotlinx.coroutines.launch

@AndroidEntryPoint
class ResultWhitelistFragment : Fragment() {

    private var _binding: FragmentResultWhitelistBinding? = null
    private val binding get() = _binding!!
    private val args: ResultWhitelistFragmentArgs by navArgs()
    private val viewModel: ResultViewModel by viewModels()

    override fun onCreateView(
        inflater: LayoutInflater, container: ViewGroup?, savedInstanceState: Bundle?
    ): View {
        _binding = FragmentResultWhitelistBinding.inflate(inflater, container, false)
        return binding.root
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)

        // 툴바 뒤로가기
        binding.toolbar.setNavigationOnClickListener {
            findNavController().navigate(R.id.action_result_whitelist_to_scan)
        }

        // URL 표시
        binding.tvUrl.text = args.url

        // 등록 경위별 설명
        binding.tvDescription.text = when (args.reason) {
            "FAVORITE"  -> "즐겨찾기에 등록된 URL이에요"
            else        -> "신뢰할 수 있는 URL이에요"  // WHITELIST
        }

        // 즐겨찾기
        viewModel.checkFavorite(args.url)

        binding.btnFavorite.setOnClickListener {
            viewModel.toggleFavorite(url = args.url, title = null, riskLevel = "SECURED")
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

        // 웹사이트 이동
        binding.btnConnect.setOnClickListener {
            viewModel.recordVisit(args.url, RiskLevel.SECURED)
            CustomTabsHelper.open(requireContext(), args.url)
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

    override fun onDestroyView() {
        super.onDestroyView()
        _binding = null
    }
}