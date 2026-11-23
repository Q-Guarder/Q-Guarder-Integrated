package com.qguarder.android.di

import com.qguarder.android.data.local.EncryptedCookieJar
import com.qguarder.android.data.remote.ApiService
import com.qguarder.android.data.remote.AuthInterceptor
import com.qguarder.android.data.remote.RefreshApiServiceHolder
import dagger.Module
import dagger.Provides
import dagger.hilt.components.SingletonComponent
import dagger.hilt.testing.TestInstallIn
import okhttp3.OkHttpClient
import okhttp3.logging.HttpLoggingInterceptor
import okhttp3.mockwebserver.MockWebServer
import retrofit2.Retrofit
import retrofit2.converter.gson.GsonConverterFactory
import java.util.concurrent.TimeUnit
import javax.inject.Singleton

/**
 * 인스트루먼트 테스트 전용 NetworkModule.
 * MockWebServer를 사용하여 실서버 의존 없이 네트워크 레이어를 테스트할 수 있음.
 *
 * 사용법:
 *   @HiltAndroidTest 클래스에서 @Inject lateinit var mockWebServer: MockWebServer
 *   테스트 시작 전 mockWebServer.enqueue(MockResponse().setBody(...))
 *   테스트 종료 후 mockWebServer.shutdown()
 */
@Module
@TestInstallIn(
    components = [SingletonComponent::class],
    replaces = [NetworkModule::class]
)
object TestNetworkModule {

    @Provides
    @Singleton
    fun provideMockWebServer(): MockWebServer = MockWebServer()

    @Provides
    @Singleton
    fun provideTestOkHttpClient(
        authInterceptor: AuthInterceptor,
        cookieJar: EncryptedCookieJar,
    ): OkHttpClient = OkHttpClient.Builder()
        .addInterceptor(authInterceptor)
        .addInterceptor(HttpLoggingInterceptor().apply {
            level = HttpLoggingInterceptor.Level.BODY
        })
        .cookieJar(cookieJar)
        .connectTimeout(5, TimeUnit.SECONDS)
        .readTimeout(5, TimeUnit.SECONDS)
        .build()

    @Provides
    @Singleton
    fun provideTestRetrofit(
        mockWebServer: MockWebServer,
        okHttpClient: OkHttpClient,
    ): Retrofit = Retrofit.Builder()
        .baseUrl(mockWebServer.url("/"))
        .client(okHttpClient)
        .addConverterFactory(GsonConverterFactory.create())
        .build()

    @Provides
    @Singleton
    fun provideTestApiService(
        retrofit: Retrofit,
        cookieJar: EncryptedCookieJar,
    ): ApiService {
        val service = retrofit.create(ApiService::class.java)
        RefreshApiServiceHolder.service = service
        return service
    }
}
