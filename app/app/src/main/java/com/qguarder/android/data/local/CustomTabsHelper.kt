package com.qguarder.android.data.local

import android.content.Context
import android.net.Uri
import androidx.browser.customtabs.CustomTabColorSchemeParams
import androidx.browser.customtabs.CustomTabsIntent

object CustomTabsHelper {

    fun open(context: Context, url: String) {
        // 툴바 색상 설정
        val colorScheme = CustomTabColorSchemeParams.Builder()
            .setToolbarColor(0xFF1A2EDB.toInt())  // Q-Guard 파란색
            .build()
        // Custom Tabs 인텐트 생성 (인텐트="이런 동작 해줘" 안드로이드에게 요청)
        CustomTabsIntent.Builder()
            // 웹페이지 제목 상단 표시
            .setShowTitle(true)
            // 라이트모드일 때 위에서 설정한 파란색 적용
            .setColorSchemeParams(
                CustomTabsIntent.COLOR_SCHEME_LIGHT, colorScheme
            )
            // 공유 버튼 표시 (url을 카카오톡 등으로 공유 가능)
            .setShareState(CustomTabsIntent.SHARE_STATE_ON)
            // 실행
            .build()
            .launchUrl(context, Uri.parse(
                if (url.startsWith("http")) url else "https://$url"
            ))
    }
}