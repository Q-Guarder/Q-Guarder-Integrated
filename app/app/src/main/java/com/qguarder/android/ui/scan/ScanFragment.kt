package com.qguarder.android.ui.scan

import android.Manifest
import android.animation.ObjectAnimator
import android.animation.ValueAnimator
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Bundle
import android.provider.Settings
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import androidx.camera.core.*
import androidx.camera.lifecycle.ProcessCameraProvider
import androidx.core.content.ContextCompat
import androidx.fragment.app.Fragment
import androidx.fragment.app.viewModels
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.lifecycleScope
import androidx.lifecycle.repeatOnLifecycle
import androidx.navigation.fragment.findNavController
import com.google.android.material.dialog.MaterialAlertDialogBuilder
import com.google.mlkit.vision.barcode.BarcodeScanning
import com.google.mlkit.vision.barcode.common.Barcode
import com.google.mlkit.vision.common.InputImage
import com.qguarder.android.BuildConfig
import com.qguarder.android.R
import com.qguarder.android.databinding.FragmentScanBinding
import dagger.hilt.android.AndroidEntryPoint
import kotlinx.coroutines.launch
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean

@AndroidEntryPoint
class ScanFragment : Fragment() {

    private var _binding: FragmentScanBinding? = null
    private val binding get() = _binding!!
    private val viewModel: ScanViewModel by viewModels()
    private lateinit var cameraExecutor: ExecutorService
    // 카메라 스레드(백그라운드)와 메인 스레드가 동시에 접근 → AtomicBoolean으로 경쟁 조건 방지
    private val isProcessing = AtomicBoolean(false)
    private var breathingAnimator: ObjectAnimator? = null

    // 스캔 화면 진입 후 이 시각까지는 QR 자동 감지를 무시 (가상 카메라 재배치 유예)
    private var scanEnabledAtMs = 0L

    private val requestPermission =
        registerForActivityResult(ActivityResultContracts.RequestPermission()) { granted ->
            if (granted) {
                hideDeniedOverlay()
                startCamera()
            } else {
                showDeniedOverlay()
            }
        }

    override fun onCreateView(
        inflater: LayoutInflater, container: ViewGroup?, savedInstanceState: Bundle?
    ): View {
        _binding = FragmentScanBinding.inflate(inflater, container, false)
        return binding.root
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)
        cameraExecutor = Executors.newSingleThreadExecutor()
        // 화면 진입 후 2초간 자동 스캔 유예 — 가상 씬 카메라를 옮길 시간 확보
        scanEnabledAtMs = System.currentTimeMillis() + 2_000L
        checkAndRequestCameraPermission()
        observeState()
        setupSimButtons()
        startBreathingAnimation()
    }

    /** 스캔 가이드 박스 호흡 애니메이션 — alpha 1.0↔0.6 반복 */
    private fun startBreathingAnimation() {
        breathingAnimator = ObjectAnimator.ofFloat(binding.scanGuide, "alpha", 1f, 0.6f).apply {
            duration = 1200
            repeatMode = ValueAnimator.REVERSE
            repeatCount = ValueAnimator.INFINITE
            start()
        }
    }

    /** 개발용 시뮬레이션 버튼 — 실제 QR 스캔 시연을 위해 항상 숨김 */
    private fun setupSimButtons() {
        binding.llSimButtons.visibility = View.GONE
    }

    // ── 권한 처리 ──────────────────────────────────────────────────

    private fun checkAndRequestCameraPermission() {
        if (ContextCompat.checkSelfPermission(requireContext(), Manifest.permission.CAMERA)
            == PackageManager.PERMISSION_GRANTED
        ) {
            hideDeniedOverlay()
            startCamera()
        } else {
            requestPermission.launch(Manifest.permission.CAMERA)
        }
    }

    /**
     * 권한 거부 시 오버레이 표시.
     *
     * shouldShowRequestPermissionRationale() 동작:
     *   - 최초 거부 후: true  → 일시 거부 → "권한 허용하기" 재요청
     *   - 영구 거부 후: false → 앱 설정만 가능 → "설정에서 허용하기"
     */
    private fun showDeniedOverlay() {
        binding.layoutPermissionDenied.visibility = View.VISIBLE

        val isPermanentlyDenied =
            !shouldShowRequestPermissionRationale(Manifest.permission.CAMERA)

        if (isPermanentlyDenied) {
            // 영구 거부 — 앱 설정으로 이동
            binding.tvPermissionDesc.text =
                "'설정 → 앱 → Q-Guard → 권한'에서\n카메라를 허용해주세요."
            binding.btnGrantPermission.text = "설정에서 허용하기"
            binding.btnGrantPermission.setOnClickListener {
                showSettingsDialog()
            }
        } else {
            // 일시 거부 — 재요청 가능
            binding.tvPermissionDesc.text =
                "QR 코드 스캔을 위해\n카메라 접근 권한이 필요합니다."
            binding.btnGrantPermission.text = "권한 허용하기"
            binding.btnGrantPermission.setOnClickListener {
                requestPermission.launch(Manifest.permission.CAMERA)
            }
        }
    }

    private fun hideDeniedOverlay() {
        binding.layoutPermissionDenied.visibility = View.GONE
    }

    /** 영구 거부 시 — 앱 설정으로 이동하기 전 이유 설명 다이얼로그 */
    private fun showSettingsDialog() {
        MaterialAlertDialogBuilder(requireContext())
            .setTitle("카메라 권한 필요")
            .setMessage("카메라 권한이 영구적으로 거부되었습니다.\n설정에서 직접 허용해야 합니다.")
            .setPositiveButton("설정으로 이동") { _, _ -> openAppSettings() }
            .setNegativeButton("취소", null)
            .show()
    }

    private fun openAppSettings() {
        startActivity(
            Intent(
                Settings.ACTION_APPLICATION_DETAILS_SETTINGS,
                Uri.fromParts("package", requireContext().packageName, null)
            )
        )
    }

    /** 설정에서 돌아왔을 때 권한 재확인 */
    override fun onResume() {
        super.onResume()
        if (ContextCompat.checkSelfPermission(requireContext(), Manifest.permission.CAMERA)
            == PackageManager.PERMISSION_GRANTED
        ) {
            if (binding.layoutPermissionDenied.visibility == View.VISIBLE) {
                // 설정에서 권한을 허용하고 돌아온 경우
                hideDeniedOverlay()
                startCamera()
            }
        }
    }

    private fun startCamera() {
        val future = ProcessCameraProvider.getInstance(requireContext())
        future.addListener({
            if (_binding == null) return@addListener
            val provider = future.get()
            val preview = Preview.Builder().build().also {
                it.surfaceProvider = binding.previewView.surfaceProvider
            }
            val analyzer = ImageAnalysis.Builder()
                .setBackpressureStrategy(ImageAnalysis.STRATEGY_KEEP_ONLY_LATEST)
                .build()
                .also { it.setAnalyzer(cameraExecutor, QrAnalyzer(::onQrDetected)) }
            try {
                provider.unbindAll()
                provider.bindToLifecycle(
                    viewLifecycleOwner, CameraSelector.DEFAULT_BACK_CAMERA, preview, analyzer
                )
            } catch (e: Exception) {
                Toast.makeText(requireContext(), "카메라 오류: ${e.message}", Toast.LENGTH_SHORT).show()
            }
        }, ContextCompat.getMainExecutor(requireContext()))
    }

    private fun onQrDetected(url: String) {
        // 진입 직후 유예 시간 동안은 무시 (돌아오자마자 같은 QR 재스캔 방지)
        if (System.currentTimeMillis() < scanEnabledAtMs) return
        // compareAndSet(false, true): false일 때만 true로 바꾸고 진행 (원자적 check-and-set)
        if (!isProcessing.compareAndSet(false, true)) return
        viewModel.analyzeUrl(url)
    }

    private fun observeState() {
        viewLifecycleOwner.lifecycleScope.launch {
            repeatOnLifecycle(Lifecycle.State.STARTED) {
                viewModel.uiState.collect { state ->
                    when (state) {
                        is ScanUiState.Idle     -> {
                            isProcessing.set(false)
                            binding.progressBar.visibility = View.GONE
                        }
                        is ScanUiState.Scanning -> {
                            // DB 조회 중 — 스피너 표시
                            binding.progressBar.visibility = View.VISIBLE
                        }
                        is ScanUiState.NavigateToScanning -> {
                            binding.progressBar.visibility = View.GONE
                            findNavController().navigate(
                                ScanFragmentDirections.actionScanToScanning(state.url)
                            )
                            viewModel.reset()
                        }
                        is ScanUiState.NavigateToWhitelist -> {
                            binding.progressBar.visibility = View.GONE
                            findNavController().navigate(
                                ScanFragmentDirections.actionScanToResultWhitelist(
                                    url    = state.url,
                                    reason = state.reason.name  // "WHITELIST" or "FAVORITE"
                                )
                            )
                            viewModel.reset()
                        }
                        is ScanUiState.Error -> {
                            isProcessing.set(false)
                            binding.progressBar.visibility = View.GONE
                            Toast.makeText(requireContext(), state.message, Toast.LENGTH_SHORT).show()
                        }
                    }
                }
            }
        }
    }

    override fun onDestroyView() {
        super.onDestroyView()
        breathingAnimator?.cancel()
        cameraExecutor.shutdown()
        _binding = null
    }
}

private class QrAnalyzer(
    private val onUrlDetected: (String) -> Unit
) : ImageAnalysis.Analyzer {
    private val scanner = BarcodeScanning.getClient()

    @ExperimentalGetImage
    override fun analyze(proxy: ImageProxy) {
        val media = proxy.image ?: run { proxy.close(); return }
        val image = InputImage.fromMediaImage(media, proxy.imageInfo.rotationDegrees)
        scanner.process(image)
            .addOnSuccessListener { barcodes ->
                barcodes.firstOrNull { it.valueType == Barcode.TYPE_URL }
                    ?.url?.url?.let { onUrlDetected(it) }
            }
            .addOnCompleteListener { proxy.close() }
    }
}