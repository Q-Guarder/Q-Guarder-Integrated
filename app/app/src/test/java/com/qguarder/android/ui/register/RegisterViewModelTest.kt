package com.qguarder.android.ui.register

import com.qguarder.android.data.remote.AuthRepository
import com.qguarder.android.domain.model.User
import io.mockk.coEvery
import io.mockk.coVerify
import io.mockk.mockk
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.UnconfinedTestDispatcher
import kotlinx.coroutines.test.resetMain
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.test.setMain
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

@OptIn(ExperimentalCoroutinesApi::class)
class RegisterViewModelTest {

    private val authRepository = mockk<AuthRepository>()
    private val testUser = User(userId = "u-1", email = "user@test.com", nickname = "홍길동")
    private lateinit var viewModel: RegisterViewModel
    private val testDispatcher = UnconfinedTestDispatcher()

    @Before
    fun setUp() {
        Dispatchers.setMain(testDispatcher)
        viewModel = RegisterViewModel(authRepository)
    }

    @After
    fun tearDown() {
        Dispatchers.resetMain()
    }

    // ── 회원가입 성공 ──────────────────────────────────────────────
    @Test
    fun registerSuccess() = runTest {
        coEvery { authRepository.register("user@test.com", "password1", "홍길동") } returns
                Result.success(testUser)

        val successEvents = mutableListOf<Unit>()
        // 이벤트가 발행되기 전에 구독이 시작되도록 Unconfined로 즉시 실행
        val job = launch(UnconfinedTestDispatcher(testScheduler)) { viewModel.registerSuccess.collect { successEvents.add(it) } }

        viewModel.register("user@test.com", "password1", "홍길동")

        assertEquals(RegisterUiState.Idle, viewModel.uiState.value)
        assertEquals(1, successEvents.size)
        job.cancel()
    }

    // ── 입력 검증 — 이메일 빈 값 ─────────────────────────────────
    @Test
    fun registerFail_emptyEmail() = runTest {
        viewModel.register("", "password1", "홍길동")

        val state = viewModel.uiState.value
        assertTrue(state is RegisterUiState.Error)
        assertEquals("이메일을 입력해주세요", (state as RegisterUiState.Error).message)
        coVerify(exactly = 0) { authRepository.register(any(), any(), any()) }
    }

    // ── 입력 검증 — 이메일 형식 오류 ─────────────────────────────
    @Test
    fun registerFail_invalidEmailFormat() = runTest {
        viewModel.register("not-an-email", "password1", "홍길동")

        val state = viewModel.uiState.value
        assertTrue(state is RegisterUiState.Error)
        assertEquals("올바른 이메일 형식이 아닙니다", (state as RegisterUiState.Error).message)
        coVerify(exactly = 0) { authRepository.register(any(), any(), any()) }
    }

    // ── 입력 검증 — 비밀번호 8자 미만 ────────────────────────────
    @Test
    fun registerFail_shortPassword() = runTest {
        viewModel.register("user@test.com", "abc", "홍길동")

        val state = viewModel.uiState.value
        assertTrue(state is RegisterUiState.Error)
        assertEquals("비밀번호는 8자 이상 입력해주세요", (state as RegisterUiState.Error).message)
        coVerify(exactly = 0) { authRepository.register(any(), any(), any()) }
    }

    // ── 입력 검증 — 닉네임 빈 값 ─────────────────────────────────
    @Test
    fun registerFail_emptyNickname() = runTest {
        viewModel.register("user@test.com", "password1", "")

        val state = viewModel.uiState.value
        assertTrue(state is RegisterUiState.Error)
        assertEquals("닉네임을 입력해주세요", (state as RegisterUiState.Error).message)
        coVerify(exactly = 0) { authRepository.register(any(), any(), any()) }
    }

    // ── 입력 검증 — 닉네임 20자 초과 ────────────────────────────
    @Test
    fun registerFail_longNickname() = runTest {
        val longNick = "a".repeat(21)
        viewModel.register("user@test.com", "password1", longNick)

        val state = viewModel.uiState.value
        assertTrue(state is RegisterUiState.Error)
        assertEquals("닉네임은 20자 이하로 입력해주세요", (state as RegisterUiState.Error).message)
        coVerify(exactly = 0) { authRepository.register(any(), any(), any()) }
    }

    // ── 서버 오류 ────────────────────────────────────────────────
    @Test
    fun registerFail_networkError() = runTest {
        coEvery { authRepository.register("user@test.com", "password1", "홍길동") } returns
                Result.failure(Exception("네트워크 오류"))

        viewModel.register("user@test.com", "password1", "홍길동")

        val state = viewModel.uiState.value
        assertTrue(state is RegisterUiState.Error)
        assertEquals("네트워크 오류", (state as RegisterUiState.Error).message)
    }

    // ── Loading 중 중복 호출 방지 ────────────────────────────────
    //
    // RegisterViewModel.register() 구조:
    //   viewModelScope.launch {
    //       _uiState.value = Loading        ← coroutine 진입 후 설정
    //       authRepository.register(...)    ← 여기서 중단
    //       _uiState.value = Idle
    //   }
    //
    // UnconfinedTestDispatcher는 코루틴을 호출 스레드에서 즉시 실행하므로
    // authRepository.register()가 CompletableDeferred.await()에 도달해 일시 중단되면
    // 그 시점에 _uiState == Loading 이고, 제어가 테스트 코드로 돌아온다.
    // 이 상태에서 두 번째 register() 호출은 Loading 가드에 막혀 무시된다.
    @Test
    fun register_duplicateCallWhileLoading_isBlocked() = runTest {
        val deferred = CompletableDeferred<Result<User>>()
        // authRepository.register()가 deferred 완료를 기다리며 일시 중단
        coEvery { authRepository.register(any(), any(), any()) } coAnswers { deferred.await() }

        // 첫 번째 호출 — coroutine이 Loading 설정 후 deferred.await()에서 일시 중단
        viewModel.register("user@test.com", "password1", "홍길동")

        // 이 시점에 _uiState == Loading 이어야 함
        assertEquals(RegisterUiState.Loading, viewModel.uiState.value)

        // 두 번째 호출 — Loading 상태이므로 즉시 return (guard)
        viewModel.register("user@test.com", "password1", "홍길동")

        // deferred 완료 → 첫 번째 coroutine 재개 → Idle 복귀
        deferred.complete(Result.success(testUser))

        // Repository는 정확히 1회만 호출됨
        coVerify(exactly = 1) { authRepository.register(any(), any(), any()) }
        assertEquals(RegisterUiState.Idle, viewModel.uiState.value)
    }
}
