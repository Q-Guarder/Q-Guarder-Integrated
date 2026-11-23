package com.qguarder.android

import android.animation.ArgbEvaluator
import android.animation.ValueAnimator
import android.content.Context
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.os.Bundle
import android.view.View
import android.view.animation.AccelerateInterpolator
import android.view.animation.DecelerateInterpolator
import android.widget.ImageView
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.appcompat.app.AppCompatDelegate
import androidx.core.view.ViewCompat
import androidx.core.view.WindowCompat
import androidx.core.view.WindowInsetsCompat
import androidx.core.view.updateLayoutParams
import androidx.core.view.updatePadding
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.lifecycleScope
import androidx.lifecycle.repeatOnLifecycle
import androidx.navigation.NavController
import androidx.navigation.NavOptions
import androidx.navigation.fragment.NavHostFragment
import com.qguarder.android.data.local.TokenManager
import com.qguarder.android.databinding.ActivityMainBinding
import dagger.hilt.android.AndroidEntryPoint
import kotlinx.coroutines.launch
import javax.inject.Inject

@AndroidEntryPoint
class MainActivity : AppCompatActivity() {

    private lateinit var binding: ActivityMainBinding
    private lateinit var navController: NavController

    @Inject lateinit var tokenManager: TokenManager

    // 헤더/탭바 숨김 대상 화면 ID
    private val hideNavDestinations = setOf(
        R.id.splashFragment,
        R.id.loginFragment,
        R.id.registerFragment,
        R.id.resultWhitelistFragment,
        R.id.resultSecuredFragment,
        R.id.resultSuspiciousFragment,
        R.id.resultBlockedFragment,
        R.id.scanningFragment,
        R.id.termsFragment,
        R.id.privacyPolicyFragment,
    )

    // 헤더 숨김 대상 (탭바도 숨기는 화면 포함)
    private val hideHeaderDestinations = setOf(
        R.id.splashFragment,
        R.id.loginFragment,
        R.id.registerFragment,
        R.id.resultWhitelistFragment,
        R.id.resultSecuredFragment,
        R.id.resultSuspiciousFragment,
        R.id.resultBlockedFragment,
        // scanningFragment는 헤더 보임
        R.id.termsFragment,
        R.id.privacyPolicyFragment,
    )

    // 현재 탭 색상 (argb 전환용)
    private var currentTabColors = mutableMapOf<View, Int>()

    // 네트워크 상태 모니터링
    private lateinit var connectivityManager: ConnectivityManager
    private val networkCallback = object : ConnectivityManager.NetworkCallback() {
        override fun onAvailable(network: Network) {
            runOnUiThread { showOfflineBanner(false) }
        }
        override fun onLost(network: Network) {
            runOnUiThread { showOfflineBanner(true) }
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        // Hilt 주입 이전에 다크모드 적용 — Activity 재생성 깜빡임 방지
        val prefs = getSharedPreferences("user_preferences", Context.MODE_PRIVATE)
        AppCompatDelegate.setDefaultNightMode(
            if (prefs.getBoolean("dark_mode", false)) AppCompatDelegate.MODE_NIGHT_YES
            else AppCompatDelegate.MODE_NIGHT_NO
        )
        super.onCreate(savedInstanceState)

        // 엣지-투-엣지: 앱을 시스템 바 뒤까지 그리기
        // API 35에서 강제 적용되므로, 하위 버전도 동일하게 처리
        WindowCompat.setDecorFitsSystemWindows(window, false)

        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)

        // 상태 바 → 헤더 상단 패딩 (내용이 상태 바에 가려지지 않도록)
        ViewCompat.setOnApplyWindowInsetsListener(binding.appHeader) { view, insets ->
            val statusBar = insets.getInsets(WindowInsetsCompat.Type.statusBars())
            view.updatePadding(top = statusBar.top)
            insets
        }

        // 내비게이션 바 → 하단 탭바 높이·패딩 동적 조정
        // 배경은 내비게이션 바 뒤까지 채우고, 탭 아이콘은 그 위에 위치
        ViewCompat.setOnApplyWindowInsetsListener(binding.customBottomNav) { view, insets ->
            val navBar = insets.getInsets(WindowInsetsCompat.Type.navigationBars())
            view.updatePadding(bottom = navBar.bottom)
            view.updateLayoutParams {
                height = resources.getDimensionPixelSize(R.dimen.bottom_nav_height) + navBar.bottom
            }
            insets
        }

        val navHostFragment = supportFragmentManager
            .findFragmentById(R.id.nav_host_fragment) as NavHostFragment
        navController = navHostFragment.navController

        // 탭 클릭 처리 — launchSingleTop: 같은 탭 중복 클릭 시 백스택 중복 방지
        val singleTop = NavOptions.Builder().setLaunchSingleTop(true).build()
        binding.tabLogs.setOnClickListener {
            navController.navigate(R.id.logsFragment, null, singleTop)
        }
        binding.tabScan.setOnClickListener {
            navController.navigate(R.id.scanFragment, null, singleTop)
        }
        binding.tabFavorites.setOnClickListener {
            navController.navigate(R.id.favoritesFragment, null, singleTop)
        }
        binding.tabProfile.setOnClickListener {
            navController.navigate(R.id.profileFragment, null, singleTop)
        }

        // 토큰 갱신 실패 시 강제 로그아웃 → 로그인 화면으로 이동
        lifecycleScope.launch {
            repeatOnLifecycle(Lifecycle.State.STARTED) {
                tokenManager.forceLogoutEvent.collect {
                    navController.navigate(
                        R.id.loginFragment,
                        null,
                        NavOptions.Builder()
                            .setPopUpTo(R.id.nav_graph, true)
                            .build()
                    )
                }
            }
        }

        // 목적지 변경 시 탭바/헤더 애니메이션 토글
        navController.addOnDestinationChangedListener { _, destination, _ ->
            val hideNav    = destination.id in hideNavDestinations
            val hideHeader = destination.id in hideHeaderDestinations

            animateVisibility(binding.customBottomNav, !hideNav)
            animateVisibility(binding.appHeader, !hideHeader)

            // 활성 탭 하이라이트 (색상 애니메이션)
            updateTabHighlight(destination.id)
        }

        // 네트워크 상태 모니터링 등록
        connectivityManager = getSystemService(ConnectivityManager::class.java)
        val request = NetworkRequest.Builder()
            .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
            .build()
        connectivityManager.registerNetworkCallback(request, networkCallback)

        // 초기 상태 확인
        val activeNetwork = connectivityManager.activeNetwork
        val capabilities = activeNetwork?.let { connectivityManager.getNetworkCapabilities(it) }
        val isOnline = capabilities?.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET) == true
        if (!isOnline) {
            binding.tvOfflineBanner.visibility = View.VISIBLE
            binding.tvOfflineBanner.alpha = 1f
        }
    }

    override fun onDestroy() {
        super.onDestroy()
        connectivityManager.unregisterNetworkCallback(networkCallback)
    }

    /** GONE/VISIBLE 직접 변환 대신 alpha + translationY 애니메이션 */
    private fun animateVisibility(view: View, show: Boolean) {
        if (show) {
            if (view.visibility == View.VISIBLE && view.alpha == 1f) return
            view.visibility = View.VISIBLE
            view.alpha = 0f
            view.translationY = if (view == binding.customBottomNav) 40f else -40f
            view.animate()
                .alpha(1f).translationY(0f)
                .setDuration(250)
                .setInterpolator(DecelerateInterpolator())
                .start()
        } else {
            if (view.visibility == View.GONE) return
            val translationTarget = if (view == binding.customBottomNav) 40f else -40f
            view.animate()
                .alpha(0f).translationY(translationTarget)
                .setDuration(200)
                .setInterpolator(AccelerateInterpolator())
                .withEndAction { view.visibility = View.GONE }
                .start()
        }
    }

    private fun updateTabHighlight(destinationId: Int) {
        val activeColor   = 0xFF3D5AFE.toInt()
        val inactiveColor = 0xFF9E9E9E.toInt()

        val logsActive      = destinationId == R.id.logsFragment
        val favoritesActive = destinationId == R.id.favoritesFragment
        val profileActive   = destinationId == R.id.profileFragment

        animateTabColor(binding.ivTabLogs, binding.tvTabLogs, if (logsActive) activeColor else inactiveColor)
        animateTabColor(binding.ivTabFavorites, binding.tvTabFavorites, if (favoritesActive) activeColor else inactiveColor)
        animateTabColor(binding.ivTabProfile, binding.tvTabProfile, if (profileActive) activeColor else inactiveColor)
    }

    /** 오프라인 배너 슬라이드 인/아웃 */
    private fun showOfflineBanner(show: Boolean) {
        val banner = binding.tvOfflineBanner
        if (show) {
            if (banner.visibility == View.VISIBLE && banner.alpha == 1f) return
            banner.visibility = View.VISIBLE
            banner.alpha = 0f
            banner.translationY = -banner.height.toFloat().coerceAtLeast(30f)
            banner.animate()
                .alpha(1f).translationY(0f)
                .setDuration(250)
                .setInterpolator(DecelerateInterpolator())
                .start()
        } else {
            if (banner.visibility == View.GONE) return
            banner.animate()
                .alpha(0f).translationY(-banner.height.toFloat().coerceAtLeast(30f))
                .setDuration(200)
                .setInterpolator(AccelerateInterpolator())
                .withEndAction { banner.visibility = View.GONE }
                .start()
        }
    }

    /** 탭 아이콘 + 텍스트 색상을 argb 보간으로 부드럽게 전환 */
    private fun animateTabColor(icon: ImageView, label: TextView, targetColor: Int) {
        val currentColor = currentTabColors[icon] ?: 0xFF9E9E9E.toInt()
        if (currentColor == targetColor) return

        ValueAnimator.ofObject(ArgbEvaluator(), currentColor, targetColor).apply {
            duration = 200
            addUpdateListener { anim ->
                val color = anim.animatedValue as Int
                icon.setColorFilter(color)
                label.setTextColor(color)
            }
            start()
        }
        currentTabColors[icon] = targetColor
    }
}
