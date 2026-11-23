package com.qguarder.android.ui.profile

import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import androidx.appcompat.app.AppCompatDelegate
import androidx.fragment.app.Fragment
import androidx.fragment.app.viewModels
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.lifecycleScope
import androidx.lifecycle.repeatOnLifecycle
import androidx.navigation.NavOptions
import androidx.navigation.fragment.findNavController
import com.qguarder.android.R
import com.qguarder.android.data.local.UserPreferences
import com.qguarder.android.databinding.FragmentProfileBinding
import dagger.hilt.android.AndroidEntryPoint
import kotlinx.coroutines.launch

@AndroidEntryPoint
class ProfileFragment : Fragment() {

    private var _binding: FragmentProfileBinding? = null
    private val binding get() = _binding!!
    private val viewModel: ProfileViewModel by viewModels()

    /** 코드에서 스위치 상태를 변경할 때 리스너 루프 방지 */
    private var isSettingDarkModeFromCode = false

    override fun onCreateView(
        inflater: LayoutInflater, container: ViewGroup?, savedInstanceState: Bundle?
    ): View {
        _binding = FragmentProfileBinding.inflate(inflater, container, false)
        return binding.root
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)
        setupClickListeners()
        observeState()
    }

    private fun setupClickListeners() {
        // ── 로그아웃 ──────────────────────────────────────
        binding.btnLogout.setOnClickListener {
            viewModel.logout()
        }

        // ── 회원정보 수정 ─────────────────────────────────
        binding.menuEditNickname.setOnClickListener {
            EditNicknameBottomSheetFragment.newInstance()
                .show(childFragmentManager, EditNicknameBottomSheetFragment.TAG)
        }

        binding.menuChangePassword.setOnClickListener {
            ChangePasswordBottomSheetFragment.newInstance()
                .show(childFragmentManager, ChangePasswordBottomSheetFragment.TAG)
        }

        // ── 히스토리 보관 기간 ────────────────────────────
        binding.menuHistoryRetention.setOnClickListener {
            HistoryRetentionBottomSheetFragment.newInstance()
                .show(childFragmentManager, HistoryRetentionBottomSheetFragment.TAG)
        }

        // ── 다크모드 토글 (행 전체 클릭 = 스위치 토글) ────
        binding.menuDarkMode.setOnClickListener {
            binding.switchDarkMode.toggle()
        }
        binding.switchDarkMode.setOnCheckedChangeListener { _, isChecked ->
            if (isSettingDarkModeFromCode) return@setOnCheckedChangeListener
            viewModel.setDarkMode(isChecked)
            AppCompatDelegate.setDefaultNightMode(
                if (isChecked) AppCompatDelegate.MODE_NIGHT_YES
                else AppCompatDelegate.MODE_NIGHT_NO
            )
        }

        // ── 회원 탈퇴 ─────────────────────────────────────
        binding.menuDeleteAccount.setOnClickListener {
            DeleteAccountBottomSheetFragment.newInstance()
                .show(childFragmentManager, DeleteAccountBottomSheetFragment.TAG)
        }

        // ── 정보 섹션 ─────────────────────────────────────
        binding.menuPrivacy.setOnClickListener {
            PrivacyPolicyBottomSheetFragment.newInstance()
                .show(childFragmentManager, PrivacyPolicyBottomSheetFragment.TAG)
        }

        binding.menuTerms.setOnClickListener {
            TermsBottomSheetFragment.newInstance()
                .show(childFragmentManager, TermsBottomSheetFragment.TAG)
        }
    }

    private fun observeState() {
        viewLifecycleOwner.lifecycleScope.launch {
            repeatOnLifecycle(Lifecycle.State.STARTED) {

                // 프로필 정보
                launch {
                    viewModel.nickname.collect { name ->
                        binding.tvNickname.text = name
                        binding.tvAvatar.text   = viewModel.avatarLetter
                    }
                }
                launch {
                    viewModel.email.collect { mail ->
                        binding.tvEmail.text = mail
                    }
                }

                // 로딩 상태 — 로그아웃 버튼 비활성화
                launch {
                    viewModel.uiState.collect { state ->
                        binding.btnLogout.isEnabled = state !is ProfileUiState.Loading
                    }
                }

                // 다크모드 스위치 동기화 (코드 변경 → 리스너 루프 방지)
                launch {
                    viewModel.darkModeEnabled.collect { enabled ->
                        isSettingDarkModeFromCode = true
                        binding.switchDarkMode.isChecked = enabled
                        isSettingDarkModeFromCode = false
                    }
                }

                // 히스토리 보관 기간 부제목 동기화
                launch {
                    viewModel.historyRetentionDays.collect { days ->
                        binding.tvHistoryRetentionValue.text = retentionLabel(days)
                    }
                }

                // 스캔 요약 통계
                launch {
                    viewModel.scanStats.collect { stats ->
                        if (stats != null) {
                            binding.tvTotalScans.text   = stats.totalScans.toString()
                            binding.tvTotalBlocked.text = (stats.blockedCount + stats.reportedCount).toString()
                            binding.tvTotalSafe.text    = stats.securedCount.toString()
                        }
                    }
                }

                // 로그아웃 성공 → 로그인 화면
                launch {
                    viewModel.logoutSuccess.collect {
                        navigateToLoginWithToast("로그아웃 되었습니다.")
                    }
                }

                // 비밀번호 변경 성공 → 로그아웃 처리됨 → 로그인 화면
                launch {
                    viewModel.passwordChangeSuccess.collect {
                        navigateToLoginWithToast("비밀번호 변경이 완료 되었습니다.")
                    }
                }

                // 회원 탈퇴 성공 → 안내 후 로그인 화면
                launch {
                    viewModel.accountDeleteSuccess.collect {
                        navigateToLoginWithToast("회원 탈퇴가 완료되었습니다.")
                    }
                }
            }
        }
    }

    private fun navigateToLoginWithToast(message: String) {
        findNavController().navigate(
            R.id.loginFragment,
            Bundle().apply { putString("toastMessage", message) },
            NavOptions.Builder()
                .setPopUpTo(R.id.nav_graph, true)
                .build()
        )
    }

    private fun retentionLabel(days: Int): String = when (days) {
        UserPreferences.RETENTION_ALL -> "전체"
        7   -> "최근 7일"
        30  -> "최근 30일"
        90  -> "최근 90일"
        180 -> "최근 180일"
        else -> "전체"
    }

    override fun onDestroyView() {
        super.onDestroyView()
        _binding = null
    }
}
