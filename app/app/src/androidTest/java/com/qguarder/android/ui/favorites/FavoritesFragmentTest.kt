package com.qguarder.android.ui.favorites

import androidx.test.espresso.Espresso.onView
import androidx.test.espresso.assertion.ViewAssertions.matches
import androidx.test.espresso.matcher.ViewMatchers.*
import com.qguarder.android.R
import com.qguarder.android.data.local.FavoriteCacheDao
import com.qguarder.android.data.local.FavoriteCacheEntity
import com.qguarder.android.launchFragmentInHiltContainer
import dagger.hilt.android.testing.HiltAndroidRule
import dagger.hilt.android.testing.HiltAndroidTest
import kotlinx.coroutines.runBlocking
import org.hamcrest.CoreMatchers.not
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import javax.inject.Inject

@HiltAndroidTest
class FavoritesFragmentTest {

    @get:Rule
    var hiltRule = HiltAndroidRule(this)

    @Inject
    lateinit var dao: FavoriteCacheDao

    @Before
    fun setUp() {
        hiltRule.inject()
    }

    @Test
    fun test_favorite_empty() {
        launchFragmentInHiltContainer<FavoritesFragment>()

        onView(withText("등록된 주소가 없습니다."))
            .check(matches(isDisplayed()))

        onView(withId(R.id.layout_empty))
            .check(matches(isDisplayed()))

        onView(withId(R.id.rv_favorites))
            .check(matches(not(isDisplayed())))
    }

    @Test
    fun test_favorite_not_empty(): Unit = runBlocking {
        // [Given] 더미 데이터
        val fakeFavorites = listOf(
            FavoriteCacheEntity(
                favoriteId = "1",
                url = "https://www.naver.com",
                title = "네이버",
                riskLevel = "SECURED",
                addedAt = "2024-03-20"
            ),
            FavoriteCacheEntity(
                favoriteId = "2",
                url = "https://www.google.com",
                title = "구글",
                riskLevel = "SECURED",
                addedAt = "2024-03-20"
            )
        )

        // DB에 직접 데이터 넣기
        fakeFavorites.forEach { dao.insert(it) }

        // [When] 화면 실행
        launchFragmentInHiltContainer<FavoritesFragment>()

        Thread.sleep(500) // Flow → ListAdapter 반영 대기

        onView(withId(R.id.layout_empty)).check(matches(not(isDisplayed())))
        onView(withId(R.id.rv_favorites)).check(matches(isDisplayed()))
        onView(withText("네이버")).check(matches(isDisplayed()))
    }
}
