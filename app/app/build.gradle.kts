import java.util.Properties
import java.io.FileInputStream

plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.android)
    alias(libs.plugins.hilt)
    alias(libs.plugins.navigation.safeargs)
    alias(libs.plugins.ksp)
}

val localProperties = Properties()
val localPropertiesFile = rootProject.file("local.properties")
if (localPropertiesFile.exists()) {
    localProperties.load(FileInputStream(localPropertiesFile))
}

android {
    namespace = "com.qguarder.android"
    compileSdk = 35

    defaultConfig {
        applicationId = "com.qguarder.android"
        minSdk = 29
        targetSdk = 35
        versionCode = 1
        versionName = "1.0"

        // Hilt 전용 테스트 러너 설정
        testInstrumentationRunner = "com.qguarder.android.HiltTestRunner"

        val baseUrl = localProperties.getProperty("BASE_URL")
            ?: error("BASE_URL이 local.properties에 정의되지 않았습니다. 'BASE_URL=https://...' 를 추가하세요.")
        buildConfigField("String", "BASE_URL", "\"$baseUrl\"")
    }
    buildFeatures {
        viewBinding = true
        buildConfig = true
    }
    // TODO: Google Play 계정 생성 후 아래 signingConfigs 블록 활성화
    //  1. Android Studio → Build → Generate Signed Bundle/APK → Create new key store
    //  2. 생성한 keystore 경로/비밀번호를 local.properties에 추가 (git 미추적)
    //     KEYSTORE_PATH=../keystore/qguarder-release.jks
    //     KEYSTORE_PASSWORD=...
    //     KEY_ALIAS=qguarder
    //     KEY_PASSWORD=...
    //  3. 아래 주석 해제
    //
    // signingConfigs {
    //     create("release") {
    //         storeFile = file(localProperties.getProperty("KEYSTORE_PATH"))
    //         storePassword = localProperties.getProperty("KEYSTORE_PASSWORD")
    //         keyAlias = localProperties.getProperty("KEY_ALIAS")
    //         keyPassword = localProperties.getProperty("KEY_PASSWORD")
    //     }
    // }

    buildTypes {
        release {
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
            // TODO: signingConfigs 활성화 후 아래 주석 해제
            // signingConfig = signingConfigs.getByName("release")
        }
        debug {
            isMinifyEnabled = false
            applicationIdSuffix = ".debug"
        }
    }
    testOptions {
        // 단위 테스트에서 android.util.Log 등 Android API 호출 시 예외 대신 기본값 반환
        unitTests.isReturnDefaultValues = true
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_11
        targetCompatibility = JavaVersion.VERSION_11
    }

    kotlinOptions {
        jvmTarget = "11"
    }

    ksp {
        arg("room.schemaLocation", "$projectDir/schemas")
    }

    packaging {
        resources {
            excludes += setOf(
                "META-INF/INDEX.LIST",
                "META-INF/DEPENDENCIES",
                "META-INF/LICENSE",
                "META-INF/LICENSE.txt",
                "META-INF/NOTICE",
                "META-INF/NOTICE.txt",
                "META-INF/AL2.0",
                "META-INF/LGPL2.1",
                "META-INF/*.kotlin_module",
                "META-INF/versions/9/previous-compilation-data.bin",
            )
        }
    }
}

dependencies {
    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.appcompat)
    implementation(libs.material)
    implementation(libs.androidx.activity)
    implementation(libs.androidx.constraintlayout)
    implementation(libs.retrofit)
    implementation(libs.retrofit.gson)
    implementation(libs.okhttp)
    implementation(libs.okhttp.logging)
    implementation(libs.hilt.android)
    implementation(libs.room.runtime)
    implementation(libs.room.ktx)
    implementation(libs.camera.camera2)
    implementation(libs.camera.lifecycle)
    implementation(libs.camera.view)
    implementation(libs.mlkit.barcode)
    implementation(libs.security.crypto)
    implementation(libs.browser)
    implementation(libs.swiperefreshlayout)
    implementation(libs.navigation.fragment)
    implementation(libs.navigation.ui)
    implementation(libs.lifecycle.viewmodel)
    implementation(libs.lifecycle.runtime)
    implementation(libs.coroutines.android)

    ksp(libs.hilt.compiler)
    ksp(libs.room.compiler)
    kspAndroidTest(libs.hilt.compiler)
    kspTest(libs.hilt.compiler)

    testImplementation(libs.junit)
    testImplementation(libs.mockk)
    testImplementation(libs.coroutines.test)
    testImplementation(libs.hilt.testing)

    androidTestImplementation(libs.androidx.junit)
    androidTestImplementation(libs.androidx.espresso.core)
    androidTestImplementation(libs.hilt.testing)
    androidTestImplementation(libs.androidx.test.core)
    androidTestImplementation(libs.androidx.test.monitor)
    androidTestImplementation(libs.okhttp.mockwebserver)
    
    debugImplementation(libs.androidx.fragment.testing)
    debugImplementation(libs.androidx.test.core)
    debugImplementation(libs.androidx.test.monitor)
}