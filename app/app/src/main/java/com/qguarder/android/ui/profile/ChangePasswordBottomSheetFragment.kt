package com.qguarder.android.ui.profile

import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import androidx.fragment.app.viewModels
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.lifecycleScope
import androidx.lifecycle.repeatOnLifecycle
import com.google.android.material.bottomsheet.BottomSheetBehavior
import com.google.android.material.bottomsheet.BottomSheetDialog
import com.google.android.material.bottomsheet.BottomSheetDialogFragment
import com.qguarder.android.R
import com.qguarder.android.databinding.BottomSheetChangePasswordBinding
import dagger.hilt.android.AndroidEntryPoint
import kotlinx.coroutines.launch

@AndroidEntryPoint
class ChangePasswordBottomSheetFragment : BottomSheetDialogFragment() {

    companion object {
        const val TAG = "ChangePasswordBottomSheet"
        fun newInstance() = ChangePasswordBottomSheetFragment()
    }

    private var _binding: BottomSheetChangePasswordBinding? = null
    private val binding get() = _binding!!

    private val viewModel: ProfileViewModel by viewModels(ownerProducer = { requireParentFragment() })

    override fun getTheme(): Int = R.style.Theme_QGuard_BottomSheet_Full

    override fun onCreateView(
        inflater: LayoutInflater, container: ViewGroup?, savedInstanceState: Bundle?
    ): View {
        _binding = BottomSheetChangePasswordBinding.inflate(inflater, container, false)
        return binding.root
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)

        (dialog as? BottomSheetDialog)?.behavior?.apply {
            state = BottomSheetBehavior.STATE_EXPANDED
            skipCollapsed = true
            isDraggable = true
        }

        binding.btnConfirm.setOnClickListener {
            binding.tvError.visibility = View.GONE
            viewModel.updatePassword(
                currentPassword = binding.etCurrentPassword.text?.toString() ?: "",
                newPassword     = binding.etNewPassword.text?.toString() ?: "",
                confirmPassword = binding.etConfirmPassword.text?.toString() ?: "",
            )
        }

        viewLifecycleOwner.lifecycleScope.launch {
            repeatOnLifecycle(Lifecycle.State.STARTED) {

                launch {
                    viewModel.uiState.collect { state ->
                        val isLoading = state is ProfileUiState.Loading
                        binding.progressBar.visibility = if (isLoading) View.VISIBLE else View.GONE
                        binding.btnConfirm.isEnabled   = !isLoading
                    }
                }

                launch {
                    viewModel.passwordChangeSuccess.collect { dismiss() }
                }

                launch {
                    viewModel.errorEvent.collect { msg ->
                        binding.tvError.text = msg
                        binding.tvError.visibility = View.VISIBLE
                    }
                }
            }
        }
    }

    override fun onDestroyView() {
        super.onDestroyView()
        _binding = null
    }
}
