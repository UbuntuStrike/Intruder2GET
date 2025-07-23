# -*- coding: utf-8 -*-

from burp import IBurpExtender, IContextMenuFactory, ITab
from java.awt import BorderLayout
from javax.swing import (
    JPanel, JButton, JFileChooser, JTextArea, JScrollPane,
    JMenuItem, JSplitPane, JTable, JLabel, JTextField
)
from javax.swing.table import DefaultTableModel
from javax.swing.border import TitledBorder
from java.awt.event import MouseAdapter
from javax.swing import JPopupMenu
from javax.swing.event import DocumentListener
import threading


class BurpExtender(IBurpExtender, IContextMenuFactory, ITab):

    PAYLOAD_PLACEHOLDER = "%s"

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self._callbacks.setExtensionName("Intruder2GET")
        self._callbacks.registerContextMenuFactory(self)

        self.selectedMessages = [None, None]  # [injectable, static]
        self.payloads = []
        self.results = []  # Store (payload, req1, resp1, req2, resp2, r1_status, r2_status)

        # === UI Setup ===
        self._mainPanel = JPanel(BorderLayout())

        # === Search box above table ===
        self.searchLabel = JLabel("Search:")
        self.searchBox = JTextField(30)

        def onSearchChange(event):
            keyword = self.searchBox.getText().lower()
            self.tableModel.setRowCount(0)
            for i, (payload, req1, resp1, req2, resp2, r1_status, r2_status) in enumerate(self.results):
                combined = (req1 + resp1 + req2 + resp2).lower()
                if keyword in combined:
                    self.tableModel.addRow([i+1, payload, len(resp1), len(resp2), r1_status, r2_status])

        class SearchDocumentListener(DocumentListener):
            def __init__(self, callback):
                self.callback = callback

            def insertUpdate(self, event):
                self.callback(event)

            def removeUpdate(self, event):
                self.callback(event)

            def changedUpdate(self, event):
                self.callback(event)

        self.searchBox.getDocument().addDocumentListener(SearchDocumentListener(onSearchChange))

        topPanel = JPanel(BorderLayout())
        topPanel.add(self.searchLabel, BorderLayout.WEST)
        topPanel.add(self.searchBox, BorderLayout.CENTER)

        # === Results Table ===
        self.tableModel = DefaultTableModel(["#", "Payload", "R1 Size", "R2 Size", "R1 Status", "R2 Status"], 0)
        self.resultTable = JTable(self.tableModel)
        self.resultTable.getSelectionModel().addListSelectionListener(self.rowSelected)

        # === Request/Response View ===
        self.request1Text = JTextArea(15, 50)
        self.request1Text.setEditable(True)
        self.request1Text.setBorder(TitledBorder("Injectable Request + Response"))

        self.request2Text = JTextArea(15, 50)
        self.request2Text.setEditable(True)
        self.request2Text.setBorder(TitledBorder("Static Request + Response"))

        self.bottomSplit = JSplitPane(JSplitPane.HORIZONTAL_SPLIT)
        self.bottomSplit.setLeftComponent(JScrollPane(self.request1Text))
        self.bottomSplit.setRightComponent(JScrollPane(self.request2Text))
        self.bottomSplit.setDividerLocation(500)

        # === Right-click to insert %s ===
        def insertPayloadAction(event):
            pos = self.request1Text.getCaretPosition()
            currentText = self.request1Text.getText()
            newText = currentText[:pos] + self.PAYLOAD_PLACEHOLDER + currentText[pos:]
            self.request1Text.setText(newText)
            self.request1Text.setCaretPosition(pos + len(self.PAYLOAD_PLACEHOLDER))

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

        self._mainPanel.add(topPanel, BorderLayout.NORTH)  # search box on top
        self._mainPanel.add(verticalSplit, BorderLayout.CENTER)
        self._mainPanel.add(self._btnPanel, BorderLayout.SOUTH)

        # === Finalize ===
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
            r1_status = response1.getStatusCode()

            byteRequest2 = self._helpers.stringToBytes(request2)
            response2 = self._callbacks.makeHttpRequest(self.selectedMessages[1].getHttpService(), byteRequest2)
            respStr2 = self._helpers.bytesToString(response2.getResponse())
            r2_status = response2.getStatusCode()

            r1_len = len(respStr1)
            r2_len = len(respStr2)

            self.results.append((payload, req1, respStr1, request2, respStr2, r1_status, r2_status))
            self.tableModel.addRow([i + 1, payload, r1_len, r2_len, r1_status, r2_status])

        self._callbacks.printOutput("Attack completed. %d payloads sent." % len(self.payloads))

    def rowSelected(self, event):
        if not event.getValueIsAdjusting():
            index = self.resultTable.getSelectedRow()
            if 0 <= index < len(self.results):
                payload, req1, resp1, req2, resp2, r1_status, r2_status = self.results[index]
                self.request1Text.setText(req1 + "\n\n--- Response (Status %d) ---\n%s" % (r1_status, resp1))
                self.request2Text.setText(req2 + "\n\n--- Response (Status %d) ---\n%s" % (r2_status, resp2))
