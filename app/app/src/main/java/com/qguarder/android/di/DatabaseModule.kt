package com.qguarder.android.di

import android.content.Context
import androidx.room.Room
import com.qguarder.android.data.local.AppDatabase
import com.qguarder.android.data.local.FavoriteCacheDao
import com.qguarder.android.data.local.ScanLogCacheDao
import com.qguarder.android.data.local.WhitelistDao
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.android.qualifiers.ApplicationContext
import dagger.hilt.components.SingletonComponent
import javax.inject.Singleton

@Module
@InstallIn(SingletonComponent::class)
object DatabaseModule {

    @Provides
    @Singleton
    fun provideAppDatabase(
        @ApplicationContext context: Context
    ): AppDatabase = Room.databaseBuilder(
        context,
        AppDatabase::class.java,
        "qguarder.db"
    )
        // TODO: 실서버 배포 전 addMigrations(MIGRATION_X_Y)로 교체 필요
        //  현재 스키마 변경 시 DB 전체 초기화됨 (사용자 데이터 손실 위험)
        .fallbackToDestructiveMigration()
        .build()

    @Provides
    @Singleton
    fun provideWhitelistDao(db: AppDatabase): WhitelistDao = db.whitelistDao()

    @Provides
    @Singleton
    fun provideFavoriteCacheDao(db: AppDatabase): FavoriteCacheDao = db.favoriteCacheDao()

    @Provides @Singleton
    fun provideScanLogCacheDao(db: AppDatabase): ScanLogCacheDao = db.scanLogCacheDao()
}