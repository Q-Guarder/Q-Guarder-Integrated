package com.qguarder.android.data.remote

import com.qguarder.android.data.local.TokenManager
import kotlinx.coroutines.runBlocking
import okhttp3.Interceptor
import okhttp3.Response
import javax.inject.Inject
import javax.inject.Singleton

@Singleton
class AuthInterceptor @Inject constructor(
    private val tokenManager: TokenManager,
) : Interceptor {

    private val noAuthPaths = listOf(
        "api/v1/auth/register",
        "api/v1/auth/login",
        "api/v1/auth/refresh",
        "api/v1/health",
    )

    // 동시 다발 401 시 refresh 중복 호출 방지용 락
    private val refreshLock = Any()

    override fun intercept(chain: Interceptor.Chain): Response {
        val request = chain.request()
        if (noAuthPaths.any { request.url.encodedPath.contains(it) }) {
            return chain.proceed(request)
        }

        val tokenUsed = tokenManager.getAccessToken()
        if (tokenUsed == null) {
            // 비로그인 상태에서 인증 필요 경로 호출 — 토큰 없이 그대로 진행
            return chain.proceed(request)
        }
        val authed = request.newBuilder()
            .header("Authorization", "Bearer $tokenUsed")
            .build()
        val response = chain.proceed(authed)

        if (response.code == 401) {
            response.close()

            val newToken = synchronized(refreshLock) {
                // 다른 스레드가 이미 갱신했으면 새 토큰 바로 사용
                val current = tokenManager.getAccessToken()
                if (current != null && current != tokenUsed) {
                    current
                } else {
                    runBlocking {
                        try {
                            val r = RefreshApiServiceHolder.service?.refreshToken()
                                ?: return@runBlocking null
                            if (r.isSuccessful) r.body()?.accessToken else null
                        } catch (e: Exception) { null }
                    }
                }
            } ?: run {
                tokenManager.clear()
                tokenManager.emitForceLogout()
                return response
            }

            tokenManager.updateAccessToken(newToken)
            return chain.proceed(
                request.newBuilder().header("Authorization", "Bearer $newToken").build()
            )
        }
        return response
    }
}

object RefreshApiServiceHolder {
    var service: ApiService? = null
}