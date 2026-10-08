package com.chameleonvpn.app

import android.content.Context
import android.net.IpPrefix
import android.net.VpnService
import android.os.Build
import androidx.annotation.RequiresApi
import java.net.InetAddress

/**
 * "Российские сайты напрямую" (split tunnelling, see docs/RU-DIRECT.md).
 *
 * Russian IPv4 networks are kept out of the tunnel so Russian services see the
 * user's own address and work at full speed; all other traffic, including DNS
 * (8.8.8.8), stays inside the VPN. The dataset is shared with the Windows
 * client: internal/rudirect/data is packaged as APK assets.
 *  - Android 13+: route 0.0.0.0/0 into the tunnel and excludeRoute() each RU prefix.
 *  - Android < 13: no route exclusion API, so only the complement list (all
 *    public IPv4 space except RU) is routed into the tunnel.
 */
object RuDirect {
 private const val DIRECT="ru-direct-v4.txt"
 private const val TUNNEL="ru-direct-complement.txt"
 private val cache=HashMap<String,List<Pair<InetAddress,Int>>>()

 @Synchronized private fun load(context:Context,name:String):List<Pair<InetAddress,Int>> = cache.getOrPut(name){
  context.assets.open(name).bufferedReader().useLines{lines->lines.map{it.trim()}.filter{it.isNotEmpty()&&!it.startsWith("#")}.mapNotNull(::parse).toList()}
 }

 internal fun parse(line:String):Pair<InetAddress,Int>?{
  val slash=line.indexOf('/');if(slash<0)return null
  val bits=line.substring(slash+1).toIntOrNull()?:return null
  val parts=line.substring(0,slash).split('.')
  if(parts.size!=4||bits !in 1..32)return null
  val bytes=ByteArray(4)
  for(i in 0..3){val v=parts[i].toIntOrNull()?:return null;if(v !in 0..255)return null;bytes[i]=v.toByte()}
  return InetAddress.getByAddress(bytes) to bits
 }

 /** Adds the split routes to [builder]; returns a short description for the log. */
 fun addRoutes(context:Context,builder:VpnService.Builder):String =
  if(Build.VERSION.SDK_INT>=33) exclude(context,builder) else include(context,builder)

 @RequiresApi(33) private fun exclude(context:Context,builder:VpnService.Builder):String{
  val list=load(context,DIRECT);check(list.isNotEmpty()){ "empty RU dataset" }
  builder.addRoute("0.0.0.0",0)
  for((address,bits) in list)builder.excludeRoute(IpPrefix(address,bits))
  return "exclude "+list.size
 }

 private fun include(context:Context,builder:VpnService.Builder):String{
  val list=load(context,TUNNEL);check(list.isNotEmpty()){ "empty RU dataset" }
  for((address,bits) in list)builder.addRoute(address,bits)
  return "include "+list.size
 }
}
