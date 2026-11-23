package com.qguarder.android.di

import android.content.Context
import androidx.room.Room
import com.qguarder.android.data.local.AppDatabase
import com.qguarder.android.data.local.FavoriteCacheDao
import com.qguarder.android.data.local.ScanLogCacheDao
import com.qguarder.android.data.local.WhitelistDao
import dagger.Module
import dagger.Provides
import dagger.hilt.android.qualifiers.ApplicationContext
import dagger.hilt.components.SingletonComponent
import dagger.hilt.testing.TestInstallIn
import javax.inject.Singleton

@Module
@TestInstallIn(
    components = [SingletonComponent::class],
    replaces = [DatabaseModule::class] // 진짜 DatabaseModule을 이 가짜로 갈아끼웁니다!
)
object TestDatabaseModule {

    @Provides
    @Singleton
    fun provideInventoryDatabase(@ApplicationContext context: Context): AppDatabase {
        // 실제 파일이 아닌 메모리에 저장되는 테스트용 DB
        return Room.inMemoryDatabaseBuilder(context, AppDatabase::class.java)
            .allowMainThreadQueries()
            .build()
    }

    @Provides
    fun provideWhitelistDao(db: AppDatabase): WhitelistDao = db.whitelistDao()

    @Provides
    fun provideFavoriteCacheDao(db: AppDatabase): FavoriteCacheDao = db.favoriteCacheDao()

    @Provides
    fun provideScanLogCacheDao(db: AppDatabase): ScanLogCacheDao = db.scanLogCacheDao()
}
