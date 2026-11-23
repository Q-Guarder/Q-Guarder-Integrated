package com.qguarder.android.ui.login

import android.os.Bundle
import android.text.SpannableString
import android.text.Spanned
import android.text.style.ForegroundColorSpan
import android.text.style.UnderlineSpan
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.Toast
import androidx.core.content.ContextCompat
import androidx.fragment.app.Fragment
import androidx.fragment.app.viewModels
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.lifecycleScope
import androidx.lifecycle.repeatOnLifecycle
import androidx.navigation.fragment.findNavController
import com.qguarder.android.R
import com.qguarder.android.databinding.FragmentLoginBinding
import dagger.hilt.android.AndroidEntryPoint
import kotlinx.coroutines.launch

@AndroidEntryPoint
class LoginFragment : Fragment() {

    private var _binding: FragmentLoginBinding? = null
    private val binding get() = _binding!!
    private val viewModel: LoginViewModel by viewModels()

    override fun onCreateView(
        inflater: LayoutInflater, container: ViewGroup?, savedInstanceState: Bundle?
    ): View {
        _binding = FragmentLoginBinding.inflate(inflater, container, false)
        return binding.root
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)

        arguments?.getString("toastMessage")?.takeIf { it.isNotEmpty() }?.let { msg ->
            Toast.makeText(requireContext(), msg, Toast.LENGTH_LONG).show()
        }

        observeState()

        binding.btnLogin.setOnClickListener {
            viewModel.onEmailChanged(binding.etEmail.text.toString())
            viewModel.onPasswordChanged(binding.etPassword.text.toString())
            viewModel.login()
        }
        binding.tvRegister.setOnClickListener {
            findNavController().navigate(R.id.action_login_to_register)
        }
        styleRegisterLink()
    }

    /** "계정이 없으신가요? 회원가입" 중 '회원가입'만 파랑 + 밑줄 */
    private fun styleRegisterLink() {
        val full = binding.tvRegister.text.toString()
        val keyword = "회원가입"
        val start = full.indexOf(keyword)
        if (start < 0) return
        val end = start + keyword.length
        val blue = ContextCompat.getColor(requireContext(), R.color.color_primary)
        binding.tvRegister.text = SpannableString(full).apply {
            setSpan(ForegroundColorSpan(blue), start, end, Spanned.SPAN_EXCLUSIVE_EXCLUSIVE)
            setSpan(UnderlineSpan(), start, end, Spanned.SPAN_EXCLUSIVE_EXCLUSIVE)
        }
    }

    private fun observeState() {
        viewLifecycleOwner.lifecycleScope.launch {
            repeatOnLifecycle(Lifecycle.State.STARTED) {
                // 로딩/에러 상태 관찰
                launch {
                    viewModel.uiState.collect { state ->
                        when (state) {
                            is LoginUiState.Idle    -> setLoading(false)
                            is LoginUiState.Loading -> setLoading(true)
                            is LoginUiState.Error   -> {
                                setLoading(false)
                                binding.etPassword.text?.clear()  // 보안: 에러 시 비밀번호 초기화
                                Toast.makeText(requireContext(), state.message, Toast.LENGTH_SHORT).show()
                            }
                        }
                    }
                }
                // 일회성 로그인 성공 이벤트 — 화면 회전 시 재실행 없음
                launch {
                    viewModel.loginSuccess.collect {
                        findNavController().navigate(R.id.action_login_to_scan)
                    }
                }
            }
        }
    }

    private fun setLoading(loading: Boolean) {
        binding.btnLogin.isEnabled  = !loading
        binding.progressBar.visibility = if (loading) View.VISIBLE else View.GONE
    }

    override fun onDestroyView() { super.onDestroyView(); _binding = null }
}