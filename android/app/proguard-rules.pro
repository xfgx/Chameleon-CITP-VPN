# gomobile calls Java via JNI names; keep the binding surface.
-keep class go.** { *; }
-keep class mobilecore.** { *; }
-keepclasseswithmembers class * { native <methods>; }
