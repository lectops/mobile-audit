package com.example;
import android.util.Log;
import android.webkit.WebView;
import android.webkit.SslErrorHandler;
public class MainActivity {
  private String password = "fake-test-password-only";
  public void configure(WebView webView, String token, SslErrorHandler handler) {
    webView.getSettings().setAllowFileAccess(true);
    Log.d("debug", token);
    handler.proceed();
  }
}
