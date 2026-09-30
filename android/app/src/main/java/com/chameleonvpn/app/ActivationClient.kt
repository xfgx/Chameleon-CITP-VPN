package com.chameleonvpn.app
import mobilecore.Mobilecore
import org.json.JSONObject
import java.net.URL
import javax.net.ssl.HttpsURLConnection
object ActivationClient {
 const val WEBSITE="https://vpn.example.com/vpn/"
 private const val API=WEBSITE+"api/v1/"
 private fun post(path:String,body:JSONObject):JSONObject {
  val connection=URL(API+path).openConnection() as HttpsURLConnection
  connection.connectTimeout=12000;connection.readTimeout=30000;connection.instanceFollowRedirects=false
  connection.requestMethod="POST";connection.doOutput=true;connection.setRequestProperty("Content-Type","application/json");connection.setRequestProperty("Accept","application/json")
  try{val bytes=body.toString().toByteArray(Charsets.UTF_8);require(bytes.size<=16384);connection.setFixedLengthStreamingMode(bytes.size);connection.outputStream.use{it.write(bytes)}
   when(val code=connection.responseCode){200->{};403->error("Ключ отозван, истёк или выдан другой установке. Получите новый QR.");409->error("Лимит устройств исчерпан. Отзовите старую установку.");429->error("Слишком много запросов. Повторите через минуту.");503->error("Выдача доступа пока недоступна. Повторите позже.");else->error("Сервис активации недоступен (HTTP $code).")}
   val result=connection.inputStream.use{stream->val out=java.io.ByteArrayOutputStream();val buffer=ByteArray(4096);while(true){val count=stream.read(buffer);if(count<0)break;require(out.size()+count<=65536){"Ответ слишком большой"};out.write(buffer,0,count)};out.toString("UTF-8")};return JSONObject(result)
  }finally{connection.disconnect()}
 }
 fun refresh(store:ProfileStore){val token=store.activationToken();require(token.isNotEmpty()){ "Получите персональный QR-код через Telegram" };val seed=store.activationSeed();val privateKey=store.clientKey{Mobilecore.genClientKey()};val transportPub=Mobilecore.pubFromPriv(privateKey);val challenge=post("challenge",JSONObject().put("token",token).put("device_public_key",Mobilecore.activationPublicKey(seed)).put("client_public_key",transportPub).put("platform","android"));require(challenge.optInt("proof_version")==1&&challenge.getString("token_digest")==Mobilecore.activationTokenDigest(token)){"Неверный ответ проверки установки"};val signature=Mobilecore.signActivation(seed,challenge.getString("challenge_id"),challenge.getString("challenge"),challenge.getString("token_digest"));require(signature.isNotEmpty());val profile=post("enroll",JSONObject().put("challenge_id",challenge.getString("challenge_id")).put("signature",signature));store.importDocument(profile.toString(),transportPub);store.setEntitlementExpiry(profile.getLong("expires_at"))}
}
