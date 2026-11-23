package com.qguarder.android.ui.register

import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.Toast
import androidx.fragment.app.Fragment
import androidx.fragment.app.viewModels
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.lifecycleScope
import androidx.lifecycle.repeatOnLifecycle
import androidx.navigation.fragment.findNavController
import com.qguarder.android.R
import com.qguarder.android.databinding.FragmentRegisterBinding
import com.qguarder.android.ui.profile.PrivacyPolicyBottomSheetFragment
import com.qguarder.android.ui.profile.TermsBottomSheetFragment
import dagger.hilt.android.AndroidEntryPoint
import kotlinx.coroutines.launch

@AndroidEntryPoint
class RegisterFragment : Fragment() {

    private var _binding: FragmentRegisterBinding? = null
    private val binding get() = _binding!!
    private val viewModel: RegisterViewModel by viewModels()

    override fun onCreateView(
        inflater: LayoutInflater, container: ViewGroup?, savedInstanceState: Bundle?
    ): View {
        _binding = FragmentRegisterBinding.inflate(inflater, container, false)
        return binding.root
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)
        setupAgreementSection()
        observeState()

        binding.btnRegister.setOnClickListener {
            viewModel.register(
                email    = binding.etEmail.text.toString(),
                password = binding.etPassword.text.toString(),
                nickname = binding.etNickname.text.toString()
            )
        }
        binding.tvLogin.setOnClickListener {
            findNavController().popBackStack()
        }
    }

    private fun setupAgreementSection() {
        // 체크박스 상태에 따라 가입 버튼 활성화/비활성화 (프로그램상 체크 시에도 동작)
        val updateButtonState = {
            binding.btnRegister.isEnabled = binding.cbTerms.isChecked && binding.cbPrivacy.isChecked
        }
        binding.cbTerms.setOnCheckedChangeListener { _, _ -> updateButtonState() }
        binding.cbPrivacy.setOnCheckedChangeListener { _, _ -> updateButtonState() }

        // 행 또는 [보기] 탭 → 무조건 약관 내용 시트 표시 (직접 체크는 막혀 있음)
        val openTerms = {
            TermsBottomSheetFragment.newInstance()
                .show(childFragmentManager, TermsBottomSheetFragment.TAG)
        }
        val openPrivacy = {
            PrivacyPolicyBottomSheetFragment.newInstance()
                .show(childFragmentManager, PrivacyPolicyBottomSheetFragment.TAG)
        }
        binding.rowTerms.setOnClickListener { openTerms() }
        binding.tvTermsLink.setOnClickListener { openTerms() }
        binding.rowPrivacy.setOnClickListener { openPrivacy() }
        binding.tvPrivacyLink.setOnClickListener { openPrivacy() }

        // 시트에서 '확인'을 눌렀을 때만 해당 항목 체크
        childFragmentManager.setFragmentResultListener(
            TermsBottomSheetFragment.REQUEST_KEY, viewLifecycleOwner
        ) { _, _ -> binding.cbTerms.isChecked = true }
        childFragmentManager.setFragmentResultListener(
            PrivacyPolicyBottomSheetFragment.REQUEST_KEY, viewLifecycleOwner
        ) { _, _ -> binding.cbPrivacy.isChecked = true }
    }

    private fun observeState() {
        viewLifecycleOwner.lifecycleScope.launch {
            repeatOnLifecycle(Lifecycle.State.STARTED) {

                // 로딩/에러 상태
                launch {
                    viewModel.uiState.collect { state ->
                        when (state) {
                            is RegisterUiState.Idle    -> setLoading(false)
                            is RegisterUiState.Loading -> setLoading(true)
                            is RegisterUiState.Error   -> {
                                setLoading(false)
                                binding.etPassword.text?.clear()  // 보안: 에러 시 비밀번호 초기화
                                Toast.makeText(requireContext(), state.message, Toast.LENGTH_SHORT).show()
                            }
                        }
                    }
                }

                // 일회성 회원가입 성공 이벤트
                launch {
                    viewModel.registerSuccess.collect {
                        Toast.makeText(requireContext(), "가입 완료! 로그인해주세요", Toast.LENGTH_SHORT).show()
                        findNavController().navigate(R.id.action_register_to_login)
                    }
                }
            }
        }
    }

    private fun setLoading(loading: Boolean) {
        val allAgreed = binding.cbTerms.isChecked && binding.cbPrivacy.isChecked
        binding.btnRegister.isEnabled  = !loading && allAgreed
        binding.progressBar.visibility = if (loading) View.VISIBLE else View.GONE
    }

    override fun onDestroyView() { super.onDestroyView(); _binding = null }
}