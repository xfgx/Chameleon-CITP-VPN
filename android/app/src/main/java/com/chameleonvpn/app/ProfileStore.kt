package com.chameleonvpn.app

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.AtomicFile
import android.util.Base64
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

class ProfileStore(private val context: Context) {
 @Synchronized fun protocol():String=read().optString("protocol","auto").let{if(it in setOf("ks","citp")) it else "auto"}
 @Synchronized fun setProtocol(mode:String){require(mode in setOf("auto","citp","ks"));write(read().put("protocol",mode))}

    @Synchronized fun activationSeed():String{val data=read();val old=data.optString("activation_seed");if(old.isNotEmpty())return old;val seed=mobilecore.Mobilecore.genActivationKey();require(seed.isNotEmpty()){ "Не удалось создать ключ установки" };write(data.put("activation_seed",seed));return seed}
    @Synchronized fun activationToken():String=read().optString("activation_token")
    @Synchronized fun setActivationToken(token:String){require(token.matches(Regex("[A-Za-z0-9_-]{10,5500}\\.[A-Za-z0-9_-]{86}"))){ "Некорректный формат персонального ключа" };write(read().put("activation_token",token).put("expires_at",0L))}
    @Synchronized fun entitlementExpiry():Long=read().optLong("expires_at",0L)
    @Synchronized fun setEntitlementExpiry(value:Long){require(value>System.currentTimeMillis()/1000){ "Срок ключа истёк" };write(read().put("expires_at",value))}

    private val file = AtomicFile(File(context.filesDir, "device-vault.bin"))
    private val alias = "chameleon-device-vault-v1"

    private fun key(): SecretKey {
        val store = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        (store.getKey(alias, null) as? SecretKey)?.let { return it }
        return KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore").apply {
            init(KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM).setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setRandomizedEncryptionRequired(true).build())
        }.generateKey()
    }

    @Synchronized private fun read(): JSONObject {
        if (!file.baseFile.exists()) return JSONObject()
        val bytes = file.openRead().use { it.readBytes() }
        require(bytes.size in 29..262144) { "Повреждено защищённое хранилище профилей" }
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, key(), GCMParameterSpec(128, bytes.copyOfRange(0, 12)))
        return JSONObject(String(cipher.doFinal(bytes.copyOfRange(12, bytes.size)), Charsets.UTF_8))
    }

    @Synchronized private fun write(value: JSONObject) {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, key())
        val stream = file.startWrite()
        try {
            stream.write(cipher.iv)
            stream.write(cipher.doFinal(value.toString().toByteArray(Charsets.UTF_8)))
            file.finishWrite(stream)
        } catch (error: Throwable) { file.failWrite(stream); throw error }
    }

    @Synchronized fun clientKey(create: () -> String): String {
        val data = read()
        val current = data.optString("client_private_key")
        if (current.isNotEmpty()) return current
        val legacy = context.getSharedPreferences("cham", Context.MODE_PRIVATE)
        val key = legacy.getString("client_priv", "").orEmpty().ifEmpty { create() }
        require(key.isNotEmpty()) { "Не удалось создать ключ устройства" }
        data.put("client_private_key", key)
        write(data)
        legacy.edit().remove("client_priv").commit()
        return key
    }

    @Synchronized fun profiles(): List<ServerProfile> {
        val array = read().optJSONArray("profiles") ?: return emptyList()
        return (0 until array.length()).map { decodeProfile(array.getJSONObject(it)) }
    }

    @Synchronized fun importDocument(text: String, ownPublicKey: String): Int {
        require(text.toByteArray().size <= 65536) { "Профиль больше 64 КиБ" }
        val document = JSONObject(text)
        require(document.optString("kind") == "chameleon-device-profile" && document.optInt("version") == 2) { "Нужен профиль версии 2 из админ-панели" }
        require(document.optInt("resolution_auth_version") == 2) { "Несовместимая версия DNS; обновите клиент и ноды" }
        val array = document.getJSONArray("servers")
        require(array.length() in 1..16) { "Профиль должен содержать от 1 до 16 подключений" }
        val profiles = (0 until array.length()).map { decodeProfile(array.getJSONObject(it)) }
        if (profiles.any { it.mode == "citp" }) {
            require(document.optString("client_public_key").trimEnd('=') == ownPublicKey.trimEnd('=')) { "Этот CITP-профиль выдан другому устройству. Передайте администратору публичный ключ этого телефона." }
        }
        val existing = mutableMapOf<String,ServerProfile>()
        profiles.forEach { existing[it.id] = it }
        require(existing.size <= 32) { "Слишком много профилей; удалите ненужные" }
        val data = read().put("profiles", JSONArray(existing.values.map { encodeProfile(it) }))
        write(data)
        return profiles.size
    }

    @Synchronized fun remove(id: String) {
        val data = read().put("profiles", JSONArray(profiles().filter { it.id != id }.map { encodeProfile(it) }))
        write(data)
    }

    private fun decodeProfile(json: JSONObject): ServerProfile {
        val profile = ServerProfile(json.getString("id"), json.getString("name"), json.getString("mode"), json.getString("addr"), json.optString("pubkey"), json.optString("subtitle"), json.optString("ks_key"), json.optString("inner"), json.optString("peer_inner"))
        require(profile.id.matches(Regex("[a-z0-9-]{3,80}")) && profile.name.length in 1..80 && profile.name.none { it.isISOControl() }) { "Некорректное название профиля" }
        val host = profile.addr.substringBeforeLast(':')
        val port = profile.addr.substringAfterLast(':').toIntOrNull()
        require(host.isNotBlank() && host.length <= 253 && !host.any { it.isWhitespace() || it == '/' || it == '\\' } && port != null && port in 1..65535) { "Некорректный адрес ноды" }
        require(profile.mode == "citp" || profile.mode == "ks") { "Неизвестный транспорт" }
        if (profile.mode == "citp") require(validKey(profile.pubkey)) { "Некорректный публичный ключ ноды" }
        if (profile.mode == "ks") {
            require(validKey(profile.ksKey) && validIPv4(profile.inner) && validIPv4(profile.peerInner) && profile.inner != profile.peerInner) { "Некорректный персональный KS-профиль" }
        }
        return profile
    }

    private fun validKey(value: String): Boolean = try { Base64.decode(value.replace('-', '+').replace('_', '/'), Base64.DEFAULT).size == 32 && value.length in 43..44 } catch (_: Exception) { false }
    private fun validIPv4(value: String): Boolean = value.split('.').let { it.size == 4 && it.all { part -> part.isNotEmpty() && part.all(Char::isDigit) && (part.toIntOrNull() ?: -1) in 0..255 } }
    private fun encodeProfile(profile: ServerProfile) = JSONObject().put("id", profile.id).put("name", profile.name).put("mode", profile.mode).put("addr", profile.addr).put("pubkey", profile.pubkey).put("subtitle", profile.subtitle).put("ks_key", profile.ksKey).put("inner", profile.inner).put("peer_inner", profile.peerInner)
}
