package com.chameleonvpn.app

import org.json.JSONObject
import java.io.BufferedReader
import java.net.HttpURLConnection
import java.net.URL
import javax.net.ssl.HttpsURLConnection

/**
 * Beta: экспериментальная RU-нога "vibecraft", доступная только по HTTPS-ссылке
 * (у виртуалки vibecraft нет своего IP). Клиент обращается к ссылке, vibecraft
 * выступает RU-входом и релеит запрос на зарубежную ногу, после чего возвращает ответ.
 *
 * Здесь — лёгкий клиент управляющего API (/api/ruvpn), которым бета проверяет
 * доступность ноги и показывает, с какого зарубежного адреса реально выходит трафик.
 * Полный L3-туннель поверх ссылки — следующий шаг в нативном ядре (mobilecore).
 */
object VibecraftLeg {
    /** Публичная ссылка на RU-вход vibecraft (без своего IP, только URL). */
    const val LINK = "https://p--v01a12b99edc370388ce63ed7cd448f02-13zpd47hxpvk-8080.sourcecraft.site"

    private const val TIMEOUT_MS = 20000

    data class Probe(
        val ok: Boolean,
        val exitLabel: String,
        val exitIp: String,
        val detail: String,
    )

    private fun open(path: String, method: String): HttpsURLConnection {
        val c = URL(LINK + path).openConnection() as HttpsURLConnection
        c.requestMethod = method
        c.connectTimeout = TIMEOUT_MS
        c.readTimeout = TIMEOUT_MS
        c.setRequestProperty("Accept", "application/json")
        return c
    }

    private fun body(c: HttpURLConnection): String {
        val stream = if (c.responseCode in 200..299) c.inputStream else c.errorStream
        return stream?.bufferedReader()?.use(BufferedReader::readText).orEmpty()
    }

    /**
     * Проверяет ногу через ссылку: сначала узнаёт список выходов, затем выполняет
     * пробный запрос наружу и возвращает реальный зарубежный адрес выхода.
     * Вызывать не на главном потоке.
     */
    fun probe(): Probe {
        try {
            val legsConn = open("/api/ruvpn/legs", "GET")
            if (legsConn.responseCode != 200) {
                return Probe(false, "", "", "RU-вход недоступен (${legsConn.responseCode}).")
            }
            val legs = JSONObject(body(legsConn))
            val exits = legs.optJSONArray("exits")
            if (exits == null || exits.length() == 0) {
                return Probe(false, "", "", "У RU-входа нет настроенных зарубежных ног.")
            }
            val exitId = exits.getJSONObject(0).optString("id")

            val fetchConn = open("/api/ruvpn/fetch", "POST")
            fetchConn.doOutput = true
            fetchConn.setRequestProperty("Content-Type", "application/json")
            val payload = JSONObject()
                .put("url", "https://ipinfo.io/json")
                .put("method", "GET")
                .put("exitId", exitId)
                .toString()
            fetchConn.outputStream.use { it.write(payload.toByteArray(Charsets.UTF_8)) }
            val text = body(fetchConn)
            if (fetchConn.responseCode != 200) {
                val err = runCatching { JSONObject(text).optString("error") }.getOrDefault("")
                return Probe(false, "", "", err.ifEmpty { "Нога вернула ${fetchConn.responseCode}." })
            }
            val result = JSONObject(text)
            val exit = result.optJSONObject("exit") ?: JSONObject()
            return Probe(
                true,
                exit.optString("label", exitId),
                exit.optString("ip", "—"),
                "Трафик вышел из-за рубежа через ссылку vibecraft.",
            )
        } catch (e: Exception) {
            return Probe(false, "", "", e.message ?: "Сеть недоступна.")
        }
    }
}
