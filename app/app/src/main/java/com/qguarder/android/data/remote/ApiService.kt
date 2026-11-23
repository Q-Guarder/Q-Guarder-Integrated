package com.qguarder.android.data.remote

import com.qguarder.android.data.remote.dto.*
import retrofit2.Response
import retrofit2.http.*

/**
 * Retrofit API 인터페이스 — v3.0
 *
 * 인증: Authorization: Bearer <access_token> — AuthInterceptor가 자동 주입
 * Refresh Token: HttpOnly 쿠키 — OkHttp CookieJar가 자동 관리
 */
interface ApiService {

    // ── 헬스체크 ──────────────────────────────────
    @GET("api/v1/health")
    suspend fun health(): Response<HealthData>

    // ── Auth (인증 불필요) ────────────────────────
    @POST("api/v1/auth/register")
    suspend fun register(
        @Body request: RegisterRequest
    ): Response<RegisterResponse>

    @POST("api/v1/auth/login")
    suspend fun login(
        @Body request: LoginRequest
    ): Response<LoginResponse>

    @POST("api/v1/auth/refresh")
    suspend fun refreshToken(): Response<RefreshResponse>
    // refresh_token은 HttpOnly 쿠키로 자동 전달 (CookieJar)

    @POST("api/v1/auth/logout")
    suspend fun logout(): Response<Map<String, String>>

    // ── 스캔 (인증 필요) ──────────────────────────
    @POST("api/v1/scan/url")
    suspend fun scanUrl(
        @Body request: ScanRequest
    ): Response<ScanResponse>

    // ── 신고 (인증 필요) ──────────────────────────
    @POST("api/v1/report")
    suspend fun report(
        @Body request: ReportRequest
    ): Response<ReportResponse>

    // ── 유저 프로필 (인증 필요) ──────────────────
    @GET("api/v1/users/me")
    suspend fun getMe(): Response<MeResponse>

    @PATCH("api/v1/users/me")
    suspend fun updateNickname(
        @Body request: UpdateNicknameRequest
    ): Response<MeResponse>

    @PATCH("api/v1/users/me/password")
    suspend fun updatePassword(
        @Body request: UpdatePasswordRequest
    ): Response<Map<String, String>>

    @HTTP(method = "DELETE", path = "api/v1/users/me", hasBody = true)
    suspend fun deleteAccount(
        @Body request: DeleteAccountRequest
    ): Response<Map<String, String>>

    // ── 사용자 기록 (인증 필요) ───────────────────
    @GET("api/v1/users/me/scan-logs")
    suspend fun getScanLogs(
        @Query("page") page: Int = 1,
        @Query("size") size: Int = 20,
        @Query("from") from: String? = null,
        @Query("to")   to:   String? = null,
    ): Response<ScanLogsResponse>

    @GET("api/v1/users/me/bookmarks")
    suspend fun getBookmarks(
        @Query("page") page: Int = 1,
        @Query("size") size: Int = 20,
    ): Response<BookmarksResponse>

    @POST("api/v1/users/me/bookmarks")
    suspend fun addBookmark(
        @Body request: AddBookmarkRequest
    ): Response<AddBookmarkResponse>

    @DELETE("api/v1/users/me/bookmarks/{bookmarkId}")
    suspend fun deleteBookmark(
        @Path("bookmarkId") bookmarkId: String
    ): Response<Map<String, String>>

    @POST("api/v1/users/me/visits")
    suspend fun addVisit(
        @Body request: AddVisitRequest
    ): Response<AddVisitResponse>

    @GET("api/v1/users/me/visits")
    suspend fun getVisits(
        @Query("page") page: Int = 1,
        @Query("size") size: Int = 20,
    ): Response<VisitsResponse>
}
