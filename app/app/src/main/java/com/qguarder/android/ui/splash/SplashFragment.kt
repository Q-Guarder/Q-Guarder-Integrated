package com.qguarder.android.ui.splash

import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.view.animation.DecelerateInterpolator
import androidx.fragment.app.Fragment
import androidx.navigation.fragment.findNavController
import com.qguarder.android.R
import com.qguarder.android.data.local.TokenManager
import com.qguarder.android.databinding.FragmentSplashBinding
import dagger.hilt.android.AndroidEntryPoint
import javax.inject.Inject

@AndroidEntryPoint
class SplashFragment : Fragment() {

    private var _binding: FragmentSplashBinding? = null
    private val binding get() = _binding!!

    @Inject lateinit var tokenManager: TokenManager

    override fun onCreateView(
        inflater: LayoutInflater, container: ViewGroup?, savedInstanceState: Bundle?
    ): View {
        _binding = FragmentSplashBinding.inflate(inflater, container, false)
        return binding.root
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)

        // 입장 애니메이션 — 로고/텍스트/버튼 순차 등장
        playEntranceAnimation()

        binding.btnStart.setOnClickListener {
            if (tokenManager.isLoggedIn()) {
                findNavController().navigate(R.id.action_splash_to_scan)
            } else {
                findNavController().navigate(R.id.action_splash_to_login)
            }
        }
    }

    private fun playEntranceAnimation() {
        val decelerate = DecelerateInterpolator(2f)
        val translationOffset = 28f * resources.displayMetrics.density  // 28dp

        // 초기 상태 설정
        binding.ivLogo.alpha = 0f
        binding.ivLogo.scaleX = 0.7f
        binding.ivLogo.scaleY = 0.7f

        binding.tvAppName.alpha = 0f
        binding.tvAppName.translationY = translationOffset

        binding.tvSubtitle.alpha = 0f

        binding.llBottom.alpha = 0f
        binding.llBottom.translationY = translationOffset * 0.5f

        // 순차 애니메이션 (60ms 간격 스태거)
        binding.ivLogo.animate()
            .alpha(1f).scaleX(1f).scaleY(1f)
            .setDuration(500).setStartDelay(100)
            .setInterpolator(decelerate).start()

        binding.tvAppName.animate()
            .alpha(1f).translationY(0f)
            .setDuration(450).setStartDelay(260)
            .setInterpolator(decelerate).start()

        binding.tvSubtitle.animate()
            .alpha(1f)
            .setDuration(400).setStartDelay(420)
            .setInterpolator(decelerate).start()

        binding.llBottom.animate()
            .alpha(1f).translationY(0f)
            .setDuration(450).setStartDelay(580)
            .setInterpolator(decelerate).start()
    }

    override fun onDestroyView() {
        super.onDestroyView()
        _binding = null
    }
}