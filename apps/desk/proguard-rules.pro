# Add project specific ProGuard rules here.
# You can control the set of applied configuration files using the
# proguardFiles setting in build.gradle.
#
# For more details, see
#   http://developer.android.com/guide/developing/tools/proguard.html

# If your project uses WebView with JS, uncomment the following
# and specify the fully qualified class name to the JavaScript interface
# class:
#-keepclassmembers class fqcn.of.javascript.interface.for.webview {
#   public *;
#}

# Uncomment this to preserve the line number information for
# debugging stack traces.
#-keepattributes SourceFile,LineNumberTable

# If you keep the line number information, uncomment this to
# hide the original source file name.
#-renamesourcefileattribute SourceFile
# Skip the optimizer entirely: it walks supertype hierarchies, and some
# Netty SSL classes extend tcnative interfaces that aren't on the classpath
# (we don't bundle native OpenSSL). For a desktop app the optimizer gains
# are negligible vs. the JDK runtime image; we just want shrinking.
-dontoptimize

# Optional / platform-specific transitive deps we don't bundle.
# These warnings are safe to suppress: the code paths that reference them
# are gated at runtime (Netty native SSL, GraalVM substitutions, optional
# compression codecs, log4j/conscrypt backends, JDK 22+ foreign-memory APIs).

# Netty optional native SSL (tcnative / OpenSSL / Conscrypt)
-dontwarn io.netty.internal.tcnative.**
-dontwarn io.netty.handler.ssl.**
-dontwarn io.netty.pkitesting.**
-dontwarn org.conscrypt.**
-dontwarn org.eclipse.jetty.npn.**
-dontwarn org.bouncycastle.jsse.**

# Netty optional compression codecs (Brotli, Zstd, LZ4, LZF, LZMA, JZlib)
-dontwarn io.netty.handler.codec.compression.**
-dontwarn io.netty.handler.codec.http.HttpContentCompressor
-dontwarn io.netty.handler.codec.http2.CompressorHttp2ConnectionEncoder
-dontwarn io.netty.handler.codec.spdy.SpdyHeaderBlockJZlibEncoder
-dontwarn com.aayushatharva.brotli4j.**
-dontwarn com.github.luben.zstd.**
-dontwarn com.jcraft.jzlib.**
-dontwarn com.ning.compress.**
-dontwarn lzma.sdk.**
-dontwarn net.jpountz.**

# Netty GraalVM-substitution classes (only used when running on GraalVM native-image)
-dontwarn io.netty.util.internal.svm.**
-dontwarn io.netty.util.NetUtilSubstitutions**
-dontwarn com.oracle.svm.core.annotate.**

# Netty JDK-22+ foreign-memory cleaners / VarHandle backports (we run on JDK 17)
-dontwarn java.lang.foreign.**
-dontwarn io.netty.util.internal.CleanerJava24Linker**
-dontwarn io.netty.util.internal.CleanerJava25**
-dontwarn io.netty.util.internal.CleanerJava9**
-dontwarn io.netty.util.internal.CleanerJava6**
-dontwarn io.netty.util.internal.PlatformDependent0**
-dontwarn io.netty.buffer.VarHandleByteBufferAccess
-dontwarn io.netty.util.concurrent.ConcurrentSkipListIntObjMultimap
-dontwarn sun.misc.Cleaner

# Netty MethodHandle/VarHandle polymorphic-signature calls — real JDK 17 APIs
# but ProGuard can't resolve their dynamically-typed signatures.
-dontwarn io.netty.util.internal.PlatformDependent
-dontwarn io.netty.util.internal.RefCnt$VarHandleRefCnt
-dontwarn io.netty.util.internal.VarHandleFactory
-dontwarn io.netty.util.internal.VarHandleReferenceCountUpdater

# log4j 1.x and 2.x backends — we route through SLF4J
-dontwarn org.apache.log4j.**
-dontwarn org.apache.logging.log4j.**
-dontwarn io.netty.util.internal.logging.Log4J2Logger
-dontwarn org.apache.commons.logging.**
-dontwarn org.slf4j.impl.StaticLoggerBinder

# Misc optional annotations / tooling integrations
-dontwarn com.google.errorprone.annotations.**
-dontwarn javax.annotation.**
-dontwarn org.osgi.annotation.bundle.**
-dontwarn reactor.blockhound.**
-dontwarn java.lang.management.**

# JetBrains Runtime shared-textures hook (only present on JBR, not Corretto/Temurin)
-dontwarn com.jetbrains.SharedTextures
-dontwarn org.jetbrains.skiko.swing.JbrSharedTexturesAdapter
