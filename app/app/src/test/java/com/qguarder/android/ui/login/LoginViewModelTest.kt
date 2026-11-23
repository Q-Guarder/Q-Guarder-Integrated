package com.qguarder.android.ui.login

import com.qguarder.android.data.remote.AuthRepository
import io.mockk.*
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.UnconfinedTestDispatcher
import kotlinx.coroutines.test.resetMain
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.test.setMain
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import org.junit.After

@OptIn(ExperimentalCoroutinesApi::class)
class LoginViewModelTest {

    private val authRepository = mockk<AuthRepository>()
    private lateinit var viewModel: LoginViewModel
    private val testDispatcher = UnconfinedTestDispatcher()

    @Before
    fun setUp() {
        Dispatchers.setMain(testDispatcher)
        viewModel = LoginViewModel(authRepository)
    }

    @After
    fun tearDown() {
        Dispatchers.resetMain()
    }

    // ── 로그인 성공 ──────────────────────────────────────────────
    // Success는 LoginUiState에서 제거되어 SharedFlow(loginSuccess)로 분리됨
    @Test
    fun loginSuccess() = runTest {
        coEvery { authRepository.login("test@test.com", "1234") } returns Result.success(Unit)

        // loginSuccess SharedFlow 수집 준비
        val successEvents = mutableListOf<Unit>()
        // 이벤트가 발행되기 전에 구독이 시작되도록 Unconfined로 즉시 실행
        val job = launch(UnconfinedTestDispatcher(testScheduler)) { viewModel.loginSuccess.collect { successEvents.add(it) } }

        viewModel.onEmailChanged("test@test.com")
        viewModel.onPasswordChanged("1234")
        viewModel.login()

        // 성공 후 uiState는 Idle로 복귀
        assertEquals(LoginUiState.Idle, viewModel.uiState.value)
        // loginSuccess 이벤트가 정확히 1회 방출됨
        assertEquals(1, successEvents.size)

        job.cancel()
    }

    // ── 로그인 실패 — 비밀번호 틀림 ──────────────────────────────
    @Test
    fun loginFail_wrongPassword() = runTest {
        coEvery { authRepository.login("test@test.com", "wrong") } returns
                Result.failure(Exception("비밀번호 틀림"))

        viewModel.onEmailChanged("test@test.com")
        viewModel.onPasswordChanged("wrong")
        viewModel.login()

        val state = viewModel.uiState.value
        assertTrue(state is LoginUiState.Error)
        assertEquals("비밀번호 틀림", (state as LoginUiState.Error).message)
    }

    // ── 로그인 실패 — 존재하지 않는 계정 ─────────────────────────
    @Test
    fun loginFail_wrongEmail() = runTest {
        coEvery { authRepository.login("wrong@test.com", "1234") } returns
                Result.failure(Exception("이메일 틀림"))

        viewModel.onEmailChanged("wrong@test.com")
        viewModel.onPasswordChanged("1234")
        viewModel.login()

        val state = viewModel.uiState.value
        assertTrue(state is LoginUiState.Error)
        assertEquals("이메일 틀림", (state as LoginUiState.Error).message)
    }

    // ── 로그인 실패 — 네트워크 오류 ──────────────────────────────
    @Test
    fun loginFail_network() = runTest {
        coEvery { authRepository.login("test@test.com", "1234") } returns
                Result.failure(Exception("네트워크 실패"))

        viewModel.onEmailChanged("test@test.com")
        viewModel.onPasswordChanged("1234")
        viewModel.login()

        val state = viewModel.uiState.value
        assertTrue(state is LoginUiState.Error)
        assertEquals("네트워크 실패", (state as LoginUiState.Error).message)
    }

    // ── 입력 검증 — 이메일 형식 오류 ─────────────────────────────
    // Repository 호출 없이 ViewModel 자체 검증에서 차단됨
    @Test
    fun loginFail_wrongEmailFormat() = runTest {
        viewModel.onEmailChanged("test.co")   // @ 없음 → 이메일 형식 아님
        viewModel.onPasswordChanged("1234")
        viewModel.login()

        val state = viewModel.uiState.value
        assertTrue(state is LoginUiState.Error)
        assertEquals("올바른 이메일 형식을 입력해주세요", (state as LoginUiState.Error).message)

        // Repository는 호출되지 않아야 함
        coVerify(exactly = 0) { authRepository.login(any(), any()) }
    }

    // ── 입력 검증 — 이메일 빈 값 ────────────────────────────────
    @Test
    fun loginFail_emptyEmail() = runTest {
        viewModel.onEmailChanged("")
        viewModel.onPasswordChanged("1234")
        viewModel.login()

        val state = viewModel.uiState.value
        assertTrue(state is LoginUiState.Error)
        assertEquals("이메일을 입력해주세요", (state as LoginUiState.Error).message)
        coVerify(exactly = 0) { authRepository.login(any(), any()) }
    }

    // ── 입력 검증 — 비밀번호 빈 값 ──────────────────────────────
    @Test
    fun loginFail_emptyPassword() = runTest {
        viewModel.onEmailChanged("test@test.com")
        viewModel.onPasswordChanged("")
        viewModel.login()

        val state = viewModel.uiState.value
        assertTrue(state is LoginUiState.Error)
        assertEquals("비밀번호를 입력해주세요", (state as LoginUiState.Error).message)
        coVerify(exactly = 0) { authRepository.login(any(), any()) }
    }
}
