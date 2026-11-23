package com.qguarder.android.ui.profile

import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import androidx.fragment.app.setFragmentResult
import com.google.android.material.bottomsheet.BottomSheetBehavior
import com.google.android.material.bottomsheet.BottomSheetDialog
import com.google.android.material.bottomsheet.BottomSheetDialogFragment
import com.qguarder.android.R
import com.qguarder.android.databinding.BottomSheetTermsBinding

class TermsBottomSheetFragment : BottomSheetDialogFragment() {

    private var _binding: BottomSheetTermsBinding? = null
    private val binding get() = _binding!!

    override fun getTheme(): Int = R.style.Theme_QGuard_BottomSheet_Full

    override fun onCreateView(
        inflater: LayoutInflater,
        container: ViewGroup?,
        savedInstanceState: Bundle?
    ): View {
        _binding = BottomSheetTermsBinding.inflate(inflater, container, false)
        return binding.root
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)

        // 다이얼로그가 완전히 펼쳐진 상태(STATE_EXPANDED)로 시작
        (dialog as? BottomSheetDialog)?.behavior?.apply {
            state = BottomSheetBehavior.STATE_EXPANDED
            skipCollapsed = true
            isDraggable = true
        }

        binding.btnClose.setOnClickListener {
            dismiss()
        }

        // 확인 → 동의 결과 전달 후 닫기
        binding.btnConfirm.setOnClickListener {
            setFragmentResult(REQUEST_KEY, Bundle.EMPTY)
            dismiss()
        }
    }

    override fun onDestroyView() {
        super.onDestroyView()
        _binding = null
    }

    companion object {
        const val TAG = "TermsBottomSheet"
        const val REQUEST_KEY = "terms_agreed_result"

        fun newInstance(): TermsBottomSheetFragment = TermsBottomSheetFragment()
    }
}
