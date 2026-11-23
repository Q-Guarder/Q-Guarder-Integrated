package com.qguarder.android.data.remote

import com.qguarder.android.data.local.EncryptedCookieJar
import com.qguarder.android.data.local.TokenManager
import com.qguarder.android.data.remote.dto.DeleteAccountRequest
import com.qguarder.android.data.remote.dto.LoginRequest
import com.qguarder.android.data.remote.dto.RegisterRequest
import com.qguarder.android.data.remote.dto.UpdateNicknameRequest
import com.qguarder.android.data.remote.dto.UpdatePasswordRequest
import com.qguarder.android.domain.model.User
import javax.inject.Inject
import javax.inject.Singleton

/*
 * 인증 Repository
 *
 * 로그인 흐름:
 * 1. POST /auth/login → access_token 수신
 * 2. 서버가 refresh_token을 HttpOnly 쿠키로 설정
 * 3. access_token을 TokenManager(EncryptedSharedPrefs)에 저장
 * 4. 이후 모든 API 요청에 AuthInterceptor가 자동으로 Bearer 헤더 추가
 * 5. 만료 시 AuthInterceptor가 /auth/refresh 자동 호출 (쿠키 자동 전달)
 */
@Singleton
class AuthRepository @Inject constructor(
    private val apiService:   ApiService,
    private val tokenManager: TokenManager,
    private val cookieJar:    EncryptedCookieJar,
) {

    /** 회원가입 */
    suspend fun register(
        email:    String,
        password: String,
        nickname: String,
    ): Result<User> {
        return try {
            val resp = apiService.register(RegisterRequest(email, password, nickname))
            if (!resp.isSuccessful || resp.body() == null) {
                return Result.failure(Exception(parseError(resp.code())))
            }
            val data = resp.body()!!
            // 회원가입 직후 userId/nickname/email 저장 — 이후 로그인 시 재활용
            tokenManager.saveUserProfile(
                userId   = data.userId,
                nickname = data.nickname,
                email    = data.email,
            )
            Result.success(
                User(
                    userId   = data.userId,
                    email    = data.email,
                    nickname = data.nickname,
                )
            )
        } catch (e: Exception) {
            Result.failure(e)
        }
    }

    /** 로그인 */
    suspend fun login(email: String, password: String): Result<Unit> {
        return try {
            val resp = apiService.login(LoginRequest(email, password))
            if (!resp.isSuccessful || resp.body() == null) {
                return Result.failure(Exception(parseError(resp.code())))
            }
            // access_token + email 저장
            // refresh_token은 HttpOnly 쿠키로 자동 저장 (CookieJar)
            tokenManager.saveAfterLogin(
                accessToken = resp.body()!!.accessToken,
                email       = email,
            )
            // userId/nickname → GET /users/me 로 조회 (실패해도 로그인은 유지)
            fetchAndSaveProfile()
            Result.success(Unit)
        } catch (e: Exception) {
            Result.failure(e)
        }
    }

    /** 서버에서 최신 유저 프로필 조회 및 TokenManager에 저장 */
    suspend fun fetchAndSaveProfile(): Result<Unit> {
        return try {
            val resp = apiService.getMe()
            if (resp.isSuccessful) {
                resp.body()?.let {
                    tokenManager.saveUserProfile(
                        userId   = it.userId,
                        nickname = it.nickname,
                        email    = it.email,
                    )
                }
                Result.success(Unit)
            } else {
                Result.failure(Exception("프로필 조회 실패 (${resp.code()})"))
            }
        } catch (e: Exception) {
            Result.failure(e)
        }
    }

    /** 로그아웃 */
    suspend fun logout() {
        try {
            apiService.logout()  // 서버 refresh_token 무효화
        } catch (_: Exception) {
            // 서버 오류여도 로컬은 반드시 삭제
        }
        tokenManager.clear()   // access_token, 프로필 삭제
        cookieJar.clear()      // refresh_token 쿠키 삭제
    }

    /** 닉네임 변경 */
    suspend fun updateNickname(nickname: String): Result<Unit> {
        return try {
            val resp = apiService.updateNickname(UpdateNicknameRequest(nickname))
            if (!resp.isSuccessful) {
                return Result.failure(Exception(parseError(resp.code())))
            }
            // 로컬 캐시 갱신
            // 서버 응답 body가 있으면 그 값을 사용하되, nickname은 요청값을 우선 적용
            // (목 서버가 구 닉네임을 그대로 반환하는 경우 대비)
            val body = resp.body()
            tokenManager.saveUserProfile(
                userId   = body?.userId   ?: tokenManager.getUserId() ?: "",
                nickname = nickname,          // ← 요청한 값으로 확정 저장
                email    = body?.email    ?: tokenManager.getEmail()  ?: "",
            )
            Result.success(Unit)
        } catch (e: Exception) {
            Result.failure(e)
        }
    }

    /** 비밀번호 변경 (성공 시 토큰 무효화 — 자동 로그아웃 필요) */
    suspend fun updatePassword(currentPassword: String, newPassword: String): Result<Unit> {
        return try {
            val resp = apiService.updatePassword(
                UpdatePasswordRequest(currentPassword, newPassword)
            )
            if (!resp.isSuccessful) {
                return Result.failure(Exception(parseError(resp.code())))
            }
            Result.success(Unit)
        } catch (e: Exception) {
            Result.failure(e)
        }
    }

    /** 회원 탈퇴 신청 (30일 유예 후 완전 삭제) */
    suspend fun deleteAccount(password: String): Result<Unit> {
        return try {
            val resp = apiService.deleteAccount(DeleteAccountRequest(password))
            if (!resp.isSuccessful) {
                return Result.failure(Exception(parseError(resp.code())))
            }
            // 로컬 세션 즉시 삭제
            tokenManager.clear()
            cookieJar.clear()
            Result.success(Unit)
        } catch (e: Exception) {
            Result.failure(e)
        }
    }

    fun isLoggedIn(): Boolean = tokenManager.isLoggedIn()

    // ── 에러 코드 → 메시지 변환 ──────────────────────
    private fun parseError(code: Int) = when (code) {
        401  -> "이메일 또는 비밀번호가 올바르지 않습니다"
        403  -> "비밀번호가 올바르지 않습니다"
        409  -> "이미 사용 중인 이메일입니다"
        422  -> "입력값을 확인해주세요"
        else -> "서버 오류가 발생했습니다 ($code)"
    }
}