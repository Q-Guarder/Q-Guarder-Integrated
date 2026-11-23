package com.qguarder.android.ui.widget

import android.animation.ValueAnimator
import android.content.Context
import android.graphics.Canvas
import android.graphics.Paint
import android.graphics.RectF
import android.util.AttributeSet
import android.view.View
import android.view.animation.DecelerateInterpolator

/*
 * 도넛 차트 — 안전(파랑) / 위협(빨강) 비율 표시
 *
 * 사용법: view.setSafePercent(67)   →  파란 호 67%, 빨간 호 33%
 * 스위프 애니메이션: 값 변경 시 800ms 감속 보간으로 호가 부드럽게 채워짐
 */
class DonutChartView @JvmOverloads constructor(
    context: Context,
    attrs: AttributeSet? = null
) : View(context, attrs) {

    private var safePercent: Int = 0
    private var displayPercent: Float = 0f  // 애니메이션 중간값

    private var sweepAnimator: ValueAnimator? = null

    private val paint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        style = Paint.Style.STROKE
    }

    private val oval = RectF()

    private val colorSafe   = 0xFF3D5AFE.toInt()
    private val colorThreat = 0xFFE53935.toInt()

    fun setSafePercent(percent: Int) {
        val clamped = percent.coerceIn(0, 100)
        if (clamped == safePercent && displayPercent == clamped.toFloat()) return

        val oldDisplay = displayPercent
        safePercent = clamped

        sweepAnimator?.cancel()
        sweepAnimator = ValueAnimator.ofFloat(oldDisplay, clamped.toFloat()).apply {
            duration = 800
            interpolator = DecelerateInterpolator(2f)
            addUpdateListener { anim ->
                displayPercent = anim.animatedValue as Float
                invalidate()
            }
            start()
        }
    }

    override fun onDraw(canvas: Canvas) {
        super.onDraw(canvas)
        if (width == 0 || height == 0) return

        val strokeWidth = width * 0.14f
        paint.strokeWidth = strokeWidth
        val inset = strokeWidth / 2f
        oval.set(inset, inset, width - inset, height - inset)

        val sweepSafe   = 360f * displayPercent / 100f
        val sweepThreat = 360f - sweepSafe

        // 전체가 0%: 빨간 원
        if (displayPercent <= 0f) {
            paint.color = colorThreat
            canvas.drawArc(oval, -90f, 360f, false, paint)
            return
        }
        // 전체가 100%: 파란 원
        if (displayPercent >= 100f) {
            paint.color = colorSafe
            canvas.drawArc(oval, -90f, 360f, false, paint)
            return
        }

        // 빨간 호 (위협)
        paint.color = colorThreat
        canvas.drawArc(oval, -90f + sweepSafe, sweepThreat, false, paint)

        // 파란 호 (안전)
        paint.color = colorSafe
        canvas.drawArc(oval, -90f, sweepSafe, false, paint)
    }

    override fun onDetachedFromWindow() {
        super.onDetachedFromWindow()
        sweepAnimator?.cancel()
    }
}
