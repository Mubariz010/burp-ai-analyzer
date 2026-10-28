# -*- coding: utf-8 -*-
"""
burp_ai_analyzer.py  —  Burp Suite AI Traffic Analyzer
=========================================================
Install:  Extender → Extensions → Add → Python → select this file
Requires: Jython 2.7 standalone JAR set in Extender → Options

What it does:
  - Intercepts every in-scope HTTP request/response
  - Forwards to local AI server (ai_analyzer_server.py) on port 8719
  - Adds a "AI Analysis" tab to Burp UI showing live findings
  - Right-click any request → "Send to AI Analyzer" for deep analysis
"""

from burp import IBurpExtender, IHttpListener, ITab, IContextMenuFactory
from javax.swing import (JPanel, JScrollPane, JTextArea, JSplitPane,
                         JLabel, JButton, JTextField, JCheckBox,
                         BoxLayout, JMenuBar, JMenuItem, JPopupMenu,
                         SwingUtilities, BorderFactory, JTabbedPane)
from javax.swing.border import EmptyBorder
from java.awt import BorderLayout, Color, Font, Dimension, FlowLayout
from java.awt.event import ActionListener
from java.net import URL, HttpURLConnection
from java.io import OutputStreamWriter, BufferedReader, InputStreamReader
from java.lang import Thread, Runnable, StringBuilder
import json
import time

AI_SERVER = "http://127.0.0.1:8719"
ANALYZER_TOKEN = ""  # must match ANALYZER_TOKEN in ai_analyzer_server.py's .env if you set one
BODY_READ_CAP = 16384  # raw bytes read from the message before truncating
BODY_KEEP = 4096        # chars kept (head+tail) after truncation, sent to the server
SKIP_CONTENT_TYPES = ("image/", "font/", "text/css", "javascript", "video/", "audio/",
                      "application/octet-stream", "application/font")


def _extract_body(raw, offset):
    """Decode a request/response body and keep its head AND tail instead of a flat cutoff,
    so a field near the end of a large JSON body isn't silently dropped before the AI ever
    sees it."""
    chunk = raw[offset:offset + BODY_READ_CAP]
    try:
        text = chunk.tostring().decode("utf-8", errors="replace")
    except:
        return "(binary)"
    if len(text) <= BODY_KEEP:
        return text
    head = int(BODY_KEEP * 0.7)
    tail = BODY_KEEP - head
    return text[:head] + "\n...[truncated]...\n" + text[-tail:]


class BurpExtender(IBurpExtender, IHttpListener, ITab, IContextMenuFactory):

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("AI Traffic Analyzer")

        # Register listeners
        callbacks.registerHttpListener(self)
        callbacks.registerContextMenuFactory(self)

        # Build UI
        self._panel = self._buildUI()
        callbacks.addSuiteTab(self)

        self._log("AI Traffic Analyzer loaded.")
        self._log("Make sure ai_analyzer_server.py is running on port 8719.")
        self._enabled = True

    # ── ITab ──────────────────────────────────────────────────────────────────
    def getTabCaption(self):
        return "AI Analyzer"

    def getUiComponent(self):
        return self._panel

    # ── IHttpListener ─────────────────────────────────────────────────────────
    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if not self._enabled:
            return
        if messageIsRequest:
            return  # analyze responses only (we include the request in the data)

        helpers = self._helpers
        req_info = helpers.analyzeRequest(messageInfo)

        # Only spend AI calls on traffic that's actually in Burp's target scope —
        # ads/CDNs/analytics beacons and out-of-scope hosts would otherwise get sent
        # to the AI too, burning budget and leaking non-target traffic to the API.
        if not self._callbacks.isInScope(req_info.getUrl()):
            return

        resp = messageInfo.getResponse()
        if not resp:
            return

        resp_info = helpers.analyzeResponse(resp)
        content_type = ""
        for h in resp_info.getHeaders():
            h_low = str(h).lower()
            if h_low.startswith("content-type:"):
                content_type = h_low
                break
        if any(x in content_type for x in SKIP_CONTENT_TYPES):
            return  # static asset — not worth an AI call

        # Run analysis in background thread to avoid blocking Burp
        runner = self._AnalysisRunner(self, messageInfo, deep=False)
        Thread(runner).start()

    # ── Context menu: right-click → "Deep AI Analysis" ───────────────────────
    def createMenuItems(self, invocation):
        from java.util import ArrayList
        items = ArrayList()
        menu = JMenuItem("Deep AI Analysis")

        def onClick(e):
            for msg in invocation.getSelectedMessages():
                runner = self._AnalysisRunner(self, msg, deep=True)
                Thread(runner).start()

        menu.addActionListener(onClick)
        items.add(menu)
        return items

    # ── Background analysis runner ────────────────────────────────────────────
    class _AnalysisRunner(Runnable):
        def __init__(self, extender, messageInfo, deep=False):
            self._ext = extender
            self._msg = messageInfo
            self._deep = deep

        def run(self):
            try:
                self._ext._analyzeMessage(self._msg, self._deep)
            except Exception as e:
                self._ext._log("[!] Analysis error: " + str(e))

    def _analyzeMessage(self, messageInfo, deep=False):
        helpers = self._helpers
        service = messageInfo.getHttpService()

        req = messageInfo.getRequest()
        resp = messageInfo.getResponse()
        if not resp:
            return

        req_info = helpers.analyzeRequest(messageInfo)
        resp_info = helpers.analyzeResponse(resp)

        # Build request dict
        req_headers = list(req_info.getHeaders())
        req_body_str = _extract_body(req, req_info.getBodyOffset())

        # Build response dict
        resp_headers = list(resp_info.getHeaders())
        resp_status = resp_info.getStatusCode()
        resp_body_str = _extract_body(resp, resp_info.getBodyOffset())

        payload = {
            "host": service.getHost(),
            "port": service.getPort(),
            "protocol": service.getProtocol(),
            "method": req_info.getMethod(),
            "url": str(req_info.getUrl()),
            "request_headers": req_headers,
            "request_body": req_body_str,
            "response_status": resp_status,
            "response_headers": resp_headers,
            "response_body": resp_body_str,
            "deep": deep,
        }

        endpoint = AI_SERVER + ("/analyze/deep" if deep else "/analyze")
        self._postToServer(endpoint, payload)

    def _postToServer(self, endpoint, data):
        try:
            url = URL(endpoint)
            conn = url.openConnection()
            conn.setRequestMethod("POST")
            conn.setDoOutput(True)
            conn.setRequestProperty("Content-Type", "application/json")
            conn.setRequestProperty("X-Analyzer-Token", ANALYZER_TOKEN)
            conn.setConnectTimeout(3000)
            conn.setReadTimeout(30000)

            writer = OutputStreamWriter(conn.getOutputStream())
            writer.write(json.dumps(data))
            writer.flush()
            writer.close()

            status = conn.getResponseCode()
            if status == 200:
                reader = BufferedReader(InputStreamReader(conn.getInputStream()))
                sb = StringBuilder()
                line = reader.readLine()
                while line:
                    sb.append(line)
                    line = reader.readLine()
                reader.close()
                result = json.loads(str(sb.toString()))
                if result.get("findings"):
                    SwingUtilities.invokeLater(
                        lambda: self._displayFinding(data, result)
                    )
        except Exception as e:
            # Server not running — silently skip, no spam
            pass

    def _displayFinding(self, request_data, result):
        findings = result.get("findings", [])
        if not findings:
            return

        url = request_data.get("url", "")
        method = request_data.get("method", "GET")
        timestamp = time.strftime("%H:%M:%S")

        for f in findings:
            severity = f.get("severity", "info").upper()
            title = f.get("title", "Finding")
            detail = f.get("detail", "")

            color_map = {"CRITICAL": Color.RED, "HIGH": Color(200, 50, 0),
                         "MEDIUM": Color(180, 120, 0), "LOW": Color(0, 100, 0),
                         "INFO": Color.GRAY}
            color = color_map.get(severity, Color.DARK_GRAY)

            # Append to findings pane
            doc = self._findings_area.getDocument()
            self._findings_area.setEditable(True)

            entry = "[{}] {} — {} {}\n  {} : {}\n\n".format(
                timestamp, severity, method, url, title, detail)
            self._findings_area.append(entry)
            self._findings_area.setEditable(False)

            # Update counter
            count = int(self._counter_label.getText().split(":")[1].strip()) + 1
            self._counter_label.setText("Findings: " + str(count))

    # ── UI builder ────────────────────────────────────────────────────────────
    def _buildUI(self):
        panel = JPanel(BorderLayout())

        # Toolbar
        toolbar = JPanel(FlowLayout(FlowLayout.LEFT, 8, 6))
        toolbar.setBorder(BorderFactory.createMatteBorder(0, 0, 1, 0, Color(200, 200, 200)))

        self._enabled_cb = JCheckBox("Enabled", True)
        self._enabled_cb.addActionListener(lambda e: setattr(self, "_enabled", self._enabled_cb.isSelected()))

        clear_btn = JButton("Clear")
        clear_btn.addActionListener(lambda e: (
            self._findings_area.setText(""),
            self._log_area.setText(""),
            self._counter_label.setText("Findings: 0")
        ))

        open_ui_btn = JButton("Open Web UI")
        open_ui_btn.addActionListener(lambda e: self._openBrowser(AI_SERVER + "/ui"))

        self._counter_label = JLabel("Findings: 0")
        self._counter_label.setFont(Font("Monospaced", Font.BOLD, 12))

        toolbar.add(self._enabled_cb)
        toolbar.add(clear_btn)
        toolbar.add(open_ui_btn)
        toolbar.add(self._counter_label)
        panel.add(toolbar, BorderLayout.NORTH)

        # Tabbed content
        tabs = JTabbedPane()

        # Findings tab
        self._findings_area = JTextArea()
        self._findings_area.setEditable(False)
        self._findings_area.setFont(Font("Monospaced", Font.PLAIN, 12))
        self._findings_area.setLineWrap(True)
        tabs.addTab("Findings", JScrollPane(self._findings_area))

        # Log tab
        self._log_area = JTextArea()
        self._log_area.setEditable(False)
        self._log_area.setFont(Font("Monospaced", Font.PLAIN, 11))
        tabs.addTab("Log", JScrollPane(self._log_area))

        panel.add(tabs, BorderLayout.CENTER)
        return panel

    def _log(self, msg):
        SwingUtilities.invokeLater(
            lambda: self._log_area.append("[{}] {}\n".format(
                time.strftime("%H:%M:%S"), msg))
        )

    def _openBrowser(self, url):
        try:
            from java.awt import Desktop
            from java.net import URI
            Desktop.getDesktop().browse(URI(url))
        except:
            self._log("Open manually: " + url)