package com.qguarder.android.ui.profile

import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import androidx.fragment.app.viewModels
import com.google.android.material.bottomsheet.BottomSheetBehavior
import com.google.android.material.bottomsheet.BottomSheetDialog
import com.google.android.material.bottomsheet.BottomSheetDialogFragment
import com.qguarder.android.R
import com.qguarder.android.data.local.UserPreferences
import com.qguarder.android.databinding.BottomSheetHistoryRetentionBinding
import dagger.hilt.android.AndroidEntryPoint

@AndroidEntryPoint
class HistoryRetentionBottomSheetFragment : BottomSheetDialogFragment() {

    companion object {
        const val TAG = "HistoryRetentionBottomSheet"
        fun newInstance() = HistoryRetentionBottomSheetFragment()
    }

    private var _binding: BottomSheetHistoryRetentionBinding? = null
    private val binding get() = _binding!!

    private val viewModel: ProfileViewModel by viewModels(ownerProducer = { requireParentFragment() })

    private val radioToDays = mapOf(
        R.id.rb_all     to UserPreferences.RETENTION_ALL,
        R.id.rb_7days   to 7,
        R.id.rb_30days  to 30,
        R.id.rb_90days  to 90,
        R.id.rb_180days to 180,
    )
    private val daysToRadio = radioToDays.entries.associate { (k, v) -> v to k }

    override fun getTheme(): Int = R.style.Theme_QGuard_BottomSheet_Full

    override fun onCreateView(
        inflater: LayoutInflater, container: ViewGroup?, savedInstanceState: Bundle?
    ): View {
        _binding = BottomSheetHistoryRetentionBinding.inflate(inflater, container, false)
        return binding.root
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)

        (dialog as? BottomSheetDialog)?.behavior?.apply {
            state = BottomSheetBehavior.STATE_EXPANDED
            skipCollapsed = true
            isDraggable = true
        }

        val currentDays = viewModel.historyRetentionDays.value
        val radioId = daysToRadio[currentDays] ?: R.id.rb_all
        binding.rgRetention.check(radioId)

        binding.btnApply.setOnClickListener {
            val selectedId   = binding.rgRetention.checkedRadioButtonId
            val selectedDays = radioToDays[selectedId] ?: UserPreferences.RETENTION_ALL
            viewModel.setHistoryRetention(selectedDays)
            dismiss()
        }
    }

    override fun onDestroyView() {
        super.onDestroyView()
        _binding = null
    }
}
