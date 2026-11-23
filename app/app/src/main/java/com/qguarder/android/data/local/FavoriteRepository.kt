package com.qguarder.android.data.local

import kotlinx.coroutines.flow.Flow
import javax.inject.Inject
import javax.inject.Singleton


@Singleton
class FavoriteRepository @Inject constructor(
    private val dao: FavoriteCacheDao
){
    fun getAll(): Flow<List<FavoriteCacheEntity>> = dao.getAll()

    suspend fun isFavorite(url: String): Boolean = dao.isFavorited(url)

    suspend fun add(entity: FavoriteCacheEntity) = dao.insert(entity)

    suspend fun remove(url: String) = dao.deleteByUrl(url)
}