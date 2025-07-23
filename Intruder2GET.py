from burp import IBurpExtender, IContextMenuFactory, ITab
from java.awt import BorderLayout
from java.io import BufferedReader, FileReader
from javax.swing import (
    JPanel, JButton, JFileChooser, JTextArea, JScrollPane,
    JMenuItem, JSplitPane, JTextField
)
from javax.swing.border import TitledBorder
from java.util import List, ArrayList
import threading


class BurpExtender(IBurpExtender, IContextMenuFactory, ITab):

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self._callbacks.setExtensionName("Intruder2GET")  # ✅ Extension name updated
        self._callbacks.registerContextMenuFactory(self)

        self.selectedMessages = []
        self.payloads = []

        # === Main Panel ===
        self._mainPanel = JPanel(BorderLayout())

        # === Top Panel: Show selected requests ===
        self.requestViewPanel = JSplitPane(JSplitPane.HORIZONTAL_SPLIT)

        self.request1Text = JTextArea(15, 50)
        self.request1Text.setEditable(False)
        self.request1Text.setBorder(TitledBorder("Request 1 (with §payload§)"))

        self.request2Text = JTextArea(15, 50)
        self.request2Text.setEditable(False)
        self.request2Text.setBorder(TitledBorder("Request 2 (sent after each payloaded request)"))

        self.requestViewPanel.setLeftComponent(JScrollPane(self.request1Text))
        self.requestViewPanel.setRightComponent(JScrollPane(self.request2Text))

        self._mainPanel.add(self.requestViewPanel, BorderLayout.NORTH)

        # === Console Output ===
        self._textArea = JTextArea(15, 80)
        self._textArea.setEditable(False)
        self._mainPanel.add(JScrollPane(self._textArea), BorderLayout.CENTER)

        # === Buttons ===
        self._btnPanel = JPanel()
        self._loadBtn = JButton("Load Wordlist", actionPerformed=self.loadWordlist)
        self._startBtn = JButton("Start Attack", actionPerformed=self.startAttack)

        self._btnPanel.add(self._loadBtn)
        self._btnPanel.add(self._startBtn)

        self._mainPanel.add(self._btnPanel, BorderLayout.SOUTH)

        # === Add tab to Burp ===
        self._callbacks.addSuiteTab(self)

    def getTabCaption(self):
        return "Intruder2GET"  # ✅ Tab caption updated

    def getUiComponent(self):
        return self._mainPanel

    def createMenuItems(self, invocation):
        messages = invocation.getSelectedMessages()
        if len(messages) == 2:
            menuItem = JMenuItem("Send to Intruder2GET", actionPerformed=lambda x: self.setRequests(messages))
            return [menuItem]
        return []

    def setRequests(self, messages):
        self.selectedMessages = messages
        self._textArea.append("Requests added.\n")

        if len(messages) != 2:
            self._textArea.append("Please select exactly 2 requests.\n")
            return

        request1Str = self._helpers.bytesToString(messages[0].getRequest())
        request2Str = self._helpers.bytesToString(messages[1].getRequest())

        self.request1Text.setText(request1Str)
        self.request2Text.setText(request2Str)

    def loadWordlist(self, event):
        chooser = JFileChooser()
        result = chooser.showOpenDialog(None)
        if result == JFileChooser.APPROVE_OPTION:
            path = chooser.getSelectedFile().getAbsolutePath()
            self.payloads = []
            with open(path, 'r') as f:
                for line in f:
                    payload = line.strip()
                    if payload:
                        self.payloads.append(payload)
            self._textArea.append(f"Loaded {len(self.payloads)} payloads.\n")

    def startAttack(self, event):
        thread = threading.Thread(target=self.runAttack)
        thread.start()

    def runAttack(self):
        if len(self.selectedMessages) != 2 or not self.payloads:
            self._textArea.append("Please load 2 requests and a payload list first.\n")
            return

        baseRequest1 = self.selectedMessages[0].getRequest()
        baseStr1 = self._helpers.bytesToString(baseRequest1)

        baseRequest2 = self.selectedMessages[1].getRequest()
        request2 = self._helpers.bytesToString(baseRequest2)

        if "§payload§" not in baseStr1:
            self._textArea.append("No §payload§ placeholder found in request 1.\n")
            return

        for i, payload in enumerate(self.payloads):
            # Replace all instances of §payload§
            modRequest1 = baseStr1.replace("§payload§", payload)
            byteRequest1 = self._helpers.stringToBytes(modRequest1)

            # Send first request
            response1 = self._callbacks.makeHttpRequest(self.selectedMessages[0].getHttpService(), byteRequest1)
            respStr1 = self._helpers.bytesToString(response1.getResponse())

            # Send second request
            byteRequest2 = self._helpers.stringToBytes(request2)
            response2 = self._callbacks.makeHttpRequest(self.selectedMessages[1].getHttpService(), byteRequest2)
            respStr2 = self._helpers.bytesToString(response2.getResponse())

            log = f"[{i+1}/{len(self.payloads)}] Payload: {payload}\n"
            log += f"Response1 Length: {len(respStr1)} | Response2 Length: {len(respStr2)}\n\n"
            self._textArea.append(log)

        self._textArea.append("Attack completed.\n")
