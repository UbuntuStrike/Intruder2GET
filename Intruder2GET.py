# -*- coding: utf-8 -*-

from burp import IBurpExtender, IContextMenuFactory, ITab
from java.awt import BorderLayout, Color
from javax.swing import (
    JPanel, JButton, JFileChooser, JTextField, JLabel,
    JScrollPane, JMenuItem, JSplitPane, JTable, JTextPane
)
from javax.swing.table import DefaultTableModel
from javax.swing.border import TitledBorder
from java.awt.event import MouseAdapter
from javax.swing import JPopupMenu
from javax.swing.event import DocumentListener
from javax.swing.text import DefaultHighlighter
import threading


class SearchDocumentListener(DocumentListener):
    def __init__(self, callback):
        self.callback = callback

    def insertUpdate(self, event):
        self.callback(event)

    def removeUpdate(self, event):
        self.callback(event)

    def changedUpdate(self, event):
        self.callback(event)


class BurpExtender(IBurpExtender, IContextMenuFactory, ITab):

    PAYLOAD_PLACEHOLDER = "%s"

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self._callbacks.setExtensionName("Intruder2GET")
        self._callbacks.registerContextMenuFactory(self)

        self.selectedMessages = [None, None]  # [injectable, static]
        self.payloads = []
        self.results = []

        self._mainPanel = JPanel(BorderLayout())

        # === Results Table ===
        self.tableModel = DefaultTableModel(["#", "Payload", "R1 Size", "R2 Size"], 0)
        self.resultTable = JTable(self.tableModel)
        self.resultTable.getSelectionModel().addListSelectionListener(self.rowSelected)

        # === Highlighter helper ===
        def highlightAllMatches(pane, keyword):
            highlighter = pane.getHighlighter()
            highlighter.removeAllHighlights()
            if not keyword:
                return
            doc = pane.getDocument()
            try:
                text = doc.getText(0, doc.getLength()).lower()
            except Exception:
                # fallback if something goes wrong
                text = pane.getText().lower()
            keyword = keyword.lower()
            pos = 0
            while True:
                index = text.find(keyword, pos)
                if index == -1:
                    break
                try:
                    highlighter.addHighlight(index, index + len(keyword),
                        DefaultHighlighter.DefaultHighlightPainter(Color.YELLOW))
                except:
                    pass
                pos = index + len(keyword)

        # === Request/Response Panels with Search ===
        self.request1Text = JTextPane()
        self.request1Text.setEditable(True)
        self.request1Text.setBorder(TitledBorder("Injectable Request + Response"))

        self.request1Search = JTextField(20)
        self.request1SearchLabel = JLabel("Search:")
        def searchRequest1(event):
            highlightAllMatches(self.request1Text, self.request1Search.getText())
        self.request1Search.getDocument().addDocumentListener(SearchDocumentListener(searchRequest1))

        request1Panel = JPanel(BorderLayout())
        topSearch1 = JPanel()
        topSearch1.add(self.request1SearchLabel)
        topSearch1.add(self.request1Search)
        request1Panel.add(topSearch1, BorderLayout.NORTH)
        request1Panel.add(JScrollPane(self.request1Text), BorderLayout.CENTER)

        self.request2Text = JTextPane()
        self.request2Text.setEditable(True)
        self.request2Text.setBorder(TitledBorder("Static Request + Response"))

        self.request2Search = JTextField(20)
        self.request2SearchLabel = JLabel("Search:")
        def searchRequest2(event):
            highlightAllMatches(self.request2Text, self.request2Search.getText())
        self.request2Search.getDocument().addDocumentListener(SearchDocumentListener(searchRequest2))

        request2Panel = JPanel(BorderLayout())
        topSearch2 = JPanel()
        topSearch2.add(self.request2SearchLabel)
        topSearch2.add(self.request2Search)
        request2Panel.add(topSearch2, BorderLayout.NORTH)
        request2Panel.add(JScrollPane(self.request2Text), BorderLayout.CENTER)

        self.bottomSplit = JSplitPane(JSplitPane.HORIZONTAL_SPLIT)
        self.bottomSplit.setLeftComponent(request1Panel)
        self.bottomSplit.setRightComponent(request2Panel)
        self.bottomSplit.setDividerLocation(500)

        # === Right-click to insert %s ===
        def insertPayloadAction(event):
            doc = self.request1Text.getStyledDocument()
            pos = self.request1Text.getCaretPosition()
            try:
                doc.insertString(pos, self.PAYLOAD_PLACEHOLDER, None)
            except Exception as e:
                self._callbacks.printError("Failed to insert payload placeholder: %s" % str(e))

        popupMenu = JPopupMenu()
        insertPayloadMenuItem = JMenuItem("Insert %s here" % self.PAYLOAD_PLACEHOLDER, actionPerformed=insertPayloadAction)
        popupMenu.add(insertPayloadMenuItem)

        class PopupListener(MouseAdapter):
            def mousePressed(self, e):
                if e.isPopupTrigger():
                    popupMenu.show(e.getComponent(), e.getX(), e.getY())

            def mouseReleased(self, e):
                if e.isPopupTrigger():
                    popupMenu.show(e.getComponent(), e.getX(), e.getY())

        self.request1Text.addMouseListener(PopupListener())

        # === Buttons ===
        self._btnPanel = JPanel()
        self._loadBtn = JButton("Load Wordlist", actionPerformed=self.loadWordlist)
        self._startBtn = JButton("Start Attack", actionPerformed=self.startAttack)
        self._btnPanel.add(self._loadBtn)
        self._btnPanel.add(self._startBtn)

        # === Layout using JSplitPane ===
        verticalSplit = JSplitPane(JSplitPane.VERTICAL_SPLIT)
        verticalSplit.setTopComponent(JScrollPane(self.resultTable))
        verticalSplit.setBottomComponent(self.bottomSplit)
        verticalSplit.setDividerLocation(200)

        self._mainPanel.add(verticalSplit, BorderLayout.CENTER)
        self._mainPanel.add(self._btnPanel, BorderLayout.SOUTH)

        self._callbacks.addSuiteTab(self)

    def getTabCaption(self):
        return "Intruder2GET"

    def getUiComponent(self):
        return self._mainPanel

    def createMenuItems(self, invocation):
        messages = invocation.getSelectedMessages()
        if messages and len(messages) == 1:
            menuItem = JMenuItem("Send to Intruder2GET", actionPerformed=lambda x: self.setRequest(messages[0]))
            return [menuItem]
        return []

    def setRequest(self, message):
        if self.selectedMessages[0] is None:
            self.selectedMessages[0] = message
            self._callbacks.printOutput("Injectable request set.")
            self.request1Text.setText(self._helpers.bytesToString(message.getRequest()))
        else:
            self.selectedMessages[1] = message
            self._callbacks.printOutput("Static request set.")
            self.request2Text.setText(self._helpers.bytesToString(message.getRequest()))

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
            self._callbacks.printOutput("Loaded %d payloads." % len(self.payloads))

    def startAttack(self, event):
        thread = threading.Thread(target=self.runAttack)
        thread.start()

    def runAttack(self):
        self.tableModel.setRowCount(0)
        self.results = []

        if None in self.selectedMessages or not self.payloads:
            self._callbacks.printOutput("Load both requests and payloads first.")
            return

        baseStr1 = self.request1Text.getText()
        request2 = self.request2Text.getText()

        if self.PAYLOAD_PLACEHOLDER not in baseStr1:
            self._callbacks.printOutput("No '%s' placeholder found in injectable request." % self.PAYLOAD_PLACEHOLDER)
            return

        for i, payload in enumerate(self.payloads):
            req1 = baseStr1.replace(self.PAYLOAD_PLACEHOLDER, payload)
            byteRequest1 = self._helpers.stringToBytes(req1)
            response1 = self._callbacks.makeHttpRequest(self.selectedMessages[0].getHttpService(), byteRequest1)
            respStr1 = self._helpers.bytesToString(response1.getResponse())

            byteRequest2 = self._helpers.stringToBytes(request2)
            response2 = self._callbacks.makeHttpRequest(self.selectedMessages[1].getHttpService(), byteRequest2)
            respStr2 = self._helpers.bytesToString(response2.getResponse())

            r1_len = len(respStr1)
            r2_len = len(respStr2)

            self.results.append((payload, req1, respStr1, request2, respStr2))
            self.tableModel.addRow([i + 1, payload, r1_len, r2_len])

        self._callbacks.printOutput("Attack completed. %d payloads sent." % len(self.payloads))

    def rowSelected(self, event):
        if not event.getValueIsAdjusting():
            index = self.resultTable.getSelectedRow()
            if 0 <= index < len(self.results):
                payload, req1, resp1, req2, resp2 = self.results[index]
                self.request1Text.setText(req1 + "\n\n--- Response ---\n" + resp1)
                self.request2Text.setText(req2 + "\n\n--- Response ---\n" + resp2)
