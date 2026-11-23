package com.qguarder.android.util

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class ValidationUtilsTest {

    // ── 정상 케이스 ────────────────────────────────────────────────

    @Test
    fun validEmail_basic_returnsTrue() {
        assertTrue(ValidationUtils.isValidEmail("user@example.com"))
    }

    @Test
    fun validEmail_withSubdomain_returnsTrue() {
        assertTrue(ValidationUtils.isValidEmail("user@mail.example.co.kr"))
    }

    @Test
    fun validEmail_withPlusSign_returnsTrue() {
        assertTrue(ValidationUtils.isValidEmail("user+tag@example.com"))
    }

    @Test
    fun validEmail_withDots_returnsTrue() {
        assertTrue(ValidationUtils.isValidEmail("first.last@example.com"))
    }

    @Test
    fun validEmail_withNumbers_returnsTrue() {
        assertTrue(ValidationUtils.isValidEmail("user123@example123.com"))
    }

    // ── 오류 케이스 ────────────────────────────────────────────────

    @Test
    fun invalidEmail_missingAt_returnsFalse() {
        assertFalse(ValidationUtils.isValidEmail("userexample.com"))
    }

    @Test
    fun invalidEmail_missingTld_returnsFalse() {
        // TLD 없이 @ 뒤에 도메인만
        assertFalse(ValidationUtils.isValidEmail("user@example"))
    }

    @Test
    fun invalidEmail_emptyString_returnsFalse() {
        assertFalse(ValidationUtils.isValidEmail(""))
    }

    @Test
    fun invalidEmail_onlyAt_returnsFalse() {
        assertFalse(ValidationUtils.isValidEmail("@"))
    }

    @Test
    fun invalidEmail_spaceInside_returnsFalse() {
        assertFalse(ValidationUtils.isValidEmail("us er@example.com"))
    }

    @Test
    fun invalidEmail_doubleAt_returnsFalse() {
        assertFalse(ValidationUtils.isValidEmail("user@@example.com"))
    }

    @Test
    fun invalidEmail_missingLocalPart_returnsFalse() {
        assertFalse(ValidationUtils.isValidEmail("@example.com"))
    }
}
