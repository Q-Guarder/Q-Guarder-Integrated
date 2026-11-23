package com.qguarder.android.ui.login

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.qguarder.android.data.remote.AuthRepository
import com.qguarder.android.util.ValidationUtils
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.*
import kotlinx.coroutines.launch
import javax.inject.Inject

sealed class LoginUiState {
    object Idle    : LoginUiState()
    object Loading : LoginUiState()
    data class Error(val message: String) : LoginUiState()
    // Success는 StateFlow가 아닌 SharedFlow로 관리 — 화면 회전 시 재실행 방지
}

@HiltViewModel
class LoginViewModel @Inject constructor(
    private val authRepository: AuthRepository
) : ViewModel() {

    private val _uiState = MutableStateFlow<LoginUiState>(LoginUiState.Idle)
    val uiState: StateFlow<LoginUiState> = _uiState.asStateFlow()

    // 일회성 네비게이션 이벤트 — collect 시점에만 실행됨
    private val _loginSuccess = MutableSharedFlow<Unit>(extraBufferCapacity = 1)
    val loginSuccess: SharedFlow<Unit> = _loginSuccess

    // 입력 필드 상태 추가
    private val _email = MutableStateFlow("")
    val email: StateFlow<String> = _email.asStateFlow()

    private val _password = MutableStateFlow("")
    val password: StateFlow<String> = _password.asStateFlow()

    // 바뀔때마다 기억
    fun onEmailChanged(value: String) {
        _email.value = value
    }

    fun onPasswordChanged(value: String) {
        _password.value = value
    }

    fun login() {
        val currentEmail    = _email.value.trim()
        val currentPassword = _password.value

        if (_uiState.value is LoginUiState.Loading) return

        // 입력값 검증
        if (currentEmail.isBlank()) {
            _uiState.value = LoginUiState.Error("이메일을 입력해주세요")
            return
        }
        if (!ValidationUtils.isValidEmail(currentEmail)) {
            _uiState.value = LoginUiState.Error("올바른 이메일 형식을 입력해주세요")
            return
        }
        if (currentPassword.isBlank()) {
            _uiState.value = LoginUiState.Error("비밀번호를 입력해주세요")
            return
        }

        viewModelScope.launch {
            _uiState.value = LoginUiState.Loading
            authRepository.login(currentEmail, currentPassword).fold(
                onSuccess = {
                    _uiState.value = LoginUiState.Idle
                    _loginSuccess.emit(Unit)
                },
                onFailure = { _uiState.value = LoginUiState.Error(it.message ?: "로그인 실패") }
            )
        }
    }
}