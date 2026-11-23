package com.qguarder.android.data

import com.qguarder.android.domain.model.ScanResult
import javax.inject.Inject
import javax.inject.Singleton

/*
 * ScanningFragment → Result*Fragment 간 분석 결과 전달용 인메모리 홀더.
 * XAI features 등 nav args로 직렬화하기 어려운 데이터를 공유한다.
 *
 * @Volatile: ScanningViewModel(코루틴)에서 쓰고 Result Fragment(메인 스레드)에서 읽으므로
 *            스레드 간 가시성 보장을 위해 필수.
 */
@Singleton
class ScanResultStore @Inject constructor() {
    @Volatile var latestSecured:    ScanResult? = null
    @Volatile var latestSuspicious: ScanResult? = null
    @Volatile var latestBlocked:    ScanResult? = null

    /** 새 스캔 시작 전 이전 결과 초기화 */
    fun clear() {
        latestSecured    = null
        latestSuspicious = null
        latestBlocked    = null
    }
}