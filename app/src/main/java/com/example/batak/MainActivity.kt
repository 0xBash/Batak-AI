package com.example.batak

import android.annotation.SuppressLint
import android.os.Build
import android.os.Bundle
import android.webkit.CookieManager
import android.webkit.WebResourceRequest
import android.webkit.WebResourceResponse
import android.webkit.WebSettings
import android.webkit.WebView
import android.webkit.WebViewClient
import androidx.activity.OnBackPressedCallback
import androidx.appcompat.app.AppCompatActivity
import java.io.ByteArrayInputStream
import java.net.URL
import java.util.concurrent.ConcurrentHashMap
import kotlin.concurrent.thread

class MainActivity : AppCompatActivity() {

    private lateinit var webView: WebView

    // Thread-safe set to hold the dynamically fetched blocklist
    private val blockedDomains = ConcurrentHashMap.newKeySet<String>()

    @SuppressLint("SetJavaScriptEnabled")
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        // 1. Fetch live StevenBlack/uBlock-style hosts list asynchronously on boot
        fetchLiveBlocklist()

        webView = findViewById(R.id.webView)

        // 2. Configure WebView baseline settings
        val webSettings: WebSettings = webView.settings
        webSettings.javaScriptEnabled = true

        // Critical for duck.ai: Stores chat histories locally via IndexedDB/Local Storage
        webSettings.domStorageEnabled = true

        // --- MODERN ANDROID SECURITY HARDENING ---

        // 3. Isolate the File System (Prevents LFI / Path Traversal from malicious JS)
        webSettings.allowFileAccess = false
        webSettings.allowContentAccess = false

        // 4. Prevent Mixed Content (Forces strict HTTPS rendering, blocks injected HTTP assets)
        webSettings.mixedContentMode = WebSettings.MIXED_CONTENT_NEVER_ALLOW

        // 5. Block Third-Party Cookies (Neutralizes cross-site tracking within the WebView)
        CookieManager.getInstance().setAcceptThirdPartyCookies(webView, false)

        // 6. Enable Google's Safe Browsing API (Checks queried URLs against malware lists)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            webSettings.safeBrowsingEnabled = true
        }

        // 7. Initialize the WebViewClient with the Ad-Blocking Interceptor
        webView.webViewClient = object : WebViewClient() {

            // Intercept and sinkhole requests matching the active blocklist
            override fun shouldInterceptRequest(
                view: WebView?,
                request: WebResourceRequest?
            ): WebResourceResponse? {
                val host = request?.url?.host?.lowercase() ?: return null

                // If domain or parent domain matches, sinkhole the connection
                if (isDomainBlocked(host)) {
                    return WebResourceResponse(
                        "text/plain",
                        "UTF-8",
                        ByteArrayInputStream("".toByteArray())
                    )
                }

                // Allow clean requests through
                return super.shouldInterceptRequest(view, request)
            }

            // Enforce sandbox navigation routing
            override fun shouldOverrideUrlLoading(
                view: WebView?,
                request: WebResourceRequest?
            ): Boolean {
                val url = request?.url?.toString() ?: return false

                if (url.startsWith("https://duck.ai")) {
                    // Return false to let the WebView load the Duck.ai URL
                    return false
                }
                // Return true to block and drop external URLs
                return true
            }
        }

        // 8. Handle the hardware back button safely
        onBackPressedDispatcher.addCallback(this, object : OnBackPressedCallback(true) {
            override fun handleOnBackPressed() {
                if (webView.canGoBack()) {
                    webView.goBack() // Navigate back in chat history
                } else {
                    finish() // Exit the app if there is no history left
                }
            }
        })

        // 9. Boot the AI assistant
        webView.loadUrl("https://duck.ai")
    }

    private fun fetchLiveBlocklist() {
        thread {
            try {
                // Fetch official raw hosts list from StevenBlack repository
                val url = URL("https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts")
                val stream = url.openStream()

                stream.bufferedReader().useLines { lines ->
                    lines.forEach { line ->
                        // Parse standard hostfile format: 0.0.0.0 bad-domain.com
                        if (line.startsWith("0.0.0.0 ")) {
                            val parts = line.split("\\s+".toRegex())
                            if (parts.size >= 2) {
                                blockedDomains.add(parts[1].lowercase())
                            }
                        }
                    }
                }
            } catch (e: Exception) {
                // Fails securely: If the device is offline, the app still boots normally
                // without blocking capabilities until the next successful launch.
                e.printStackTrace()
            }
        }
    }

    private fun isDomainBlocked(host: String): Boolean {
        // Direct match check
        if (blockedDomains.contains(host)) return true

        // Root domain check (handles subdomains like tracker.bad-domain.com)
        val parts = host.split(".")
        if (parts.size > 2) {
            val mainDomain = parts.takeLast(2).joinToString(".")
            return blockedDomains.contains(mainDomain)
        }
        return false
    }
}