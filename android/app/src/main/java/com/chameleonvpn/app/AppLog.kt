package com.chameleonvpn.app
import android.content.Context
// Release builds write neither logcat nor files. No analytics SDK is used.
object AppLog {
 fun init(context:Context){mobilecore.Mobilecore.setDiagnosticsEnabled(BuildConfig.DEBUG);mobilecore.Mobilecore.setLogPath("")}
 fun d(tag:String,message:String){if(BuildConfig.DEBUG)android.util.Log.d("Chameleon/"+tag,safe(message))}
 fun i(tag:String,message:String){if(BuildConfig.DEBUG)android.util.Log.i("Chameleon/"+tag,safe(message))}
 fun e(tag:String,message:String,error:Throwable?=null){if(BuildConfig.DEBUG)android.util.Log.e("Chameleon/"+tag,safe(message))}
 private fun safe(value:String)=value.replace(Regex("[A-Za-z0-9_+/-]{43,}={0,2}"),"[REDACTED]").take(1024)
}
