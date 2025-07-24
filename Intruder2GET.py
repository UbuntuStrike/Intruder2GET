# -*- coding: utf-8 -*-

from burp import IBurpExtender, IContextMenuFactory, ITab
from java.awt import BorderLayout, Color, FlowLayout
from javax.swing import (
    JPanel, JButton, JFileChooser, JTextField, JLabel,
    JScrollPane, JMenuItem, JSplitPane, JTable, JTextPane, JCheckBox,
    JRadioButton, ButtonGroup
)
from javax.swing.table import DefaultTableModel
from java.awt.event import MouseAdapter
from javax.swing import JPopupMenu
from javax.swing.event import DocumentListener
from javax.swing.text import DefaultHighlighter
import threading

class SearchDocumentListener(DocumentListener):
    def __init__(self, callback):
        self.callback = callback
    def insertUpdate(self, event): self.callback(event)
    def removeUpdate(self, event): self.callback(event)
    def changedUpdate(self, event): self.callback(event)

class BurpExtender(IBurpExtender, IContextMenuFactory, ITab):

    PAYLOAD_PLACEHOLDER = "%s"

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self._callbacks.setExtensionName("Intruder2GET")
        self._callbacks.registerContextMenuFactory(self)

        self._mainPanel = JPanel(BorderLayout())
        self.initUI()
        self._callbacks.addSuiteTab(self)

    def initUI(self):
        self.selectedMessages = [None, None]
        self.payloads = []
        self.results = []

        self.tableModel = DefaultTableModel(["#", "Payload", "R1 Size", "R2 Size"], 0)
        self.resultTable = JTable(self.tableModel)
        self.resultTable.getSelectionModel().addListSelectionListener(self.rowSelected)

        def highlightAllMatches(pane, keyword):
            highlighter = pane.getHighlighter()
            highlighter.removeAllHighlights()
            if not keyword:
                return
            try:
                text = pane.getDocument().getText(0, pane.getDocument().getLength()).lower()
                keyword = keyword.lower()
                pos = 0
                while True:
                    index = text.find(keyword, pos)
                    if index == -1:
                        break
                    highlighter.addHighlight(index, index + len(keyword),
                        DefaultHighlighter.DefaultHighlightPainter(Color.YELLOW))
                    pos = index + len(keyword)
            except:
                pass

        self.request1State = {'req': '', 'resp': '', 'html': False, 'mode': 'request'}
        self.request2State = {'req': '', 'resp': '', 'html': False, 'mode': 'request'}

        def buildPane(state, highlightFunc):
            textPane = JTextPane()
            textPane.setEditable(True)
            textPane.setContentType("text/plain")

            search = JTextField(20)
            search.getDocument().addDocumentListener(SearchDocumentListener(lambda e: highlightFunc(textPane, search.getText())))
            toggle = JCheckBox("Render HTML")
            toggle.setSelected(False)

            radioReq = JRadioButton("Request", True)
            radioResp = JRadioButton("Response")
            group = ButtonGroup()
            group.add(radioReq)
            group.add(radioResp)

            def updateView():
                mode = 'request' if radioReq.isSelected() else 'response'
                state['mode'] = mode
                state['html'] = toggle.isSelected()
                textPane.setContentType("text/html" if (mode == 'response' and state['html']) else "text/plain")
                content = state['req'] if mode == 'request' else state['resp']
                if mode == 'response' and state['html']:
                    content = self.wrapHtml(content)
                textPane.setText(content)

            toggle.addActionListener(lambda e: updateView())
            radioReq.addActionListener(lambda e: updateView())
            radioResp.addActionListener(lambda e: updateView())

            searchPanel = JPanel(FlowLayout(FlowLayout.LEFT))
            searchPanel.add(JLabel("Search:"))
            searchPanel.add(search)
            searchPanel.add(toggle)
            searchPanel.add(radioReq)
            searchPanel.add(radioResp)

            container = JPanel(BorderLayout())
            container.add(searchPanel, BorderLayout.NORTH)
            container.add(JScrollPane(textPane), BorderLayout.CENTER)

            return container, textPane, toggle, radioReq, radioResp, updateView

        panel1, self.request1Text, self.req1Toggle, self.req1RadioReq, self.req1RadioResp, self.request1UpdateView = buildPane(self.request1State, highlightAllMatches)
        panel2, self.request2Text, self.req2Toggle, self.req2RadioReq, self.req2RadioResp, self.request2UpdateView = buildPane(self.request2State, highlightAllMatches)

        self.bottomSplit = JSplitPane(JSplitPane.HORIZONTAL_SPLIT)
        self.bottomSplit.setLeftComponent(panel1)
        self.bottomSplit.setRightComponent(panel2)
        self.bottomSplit.setDividerLocation(500)

        def insertPayloadAction(event):
            pos = self.request1Text.getCaretPosition()
            try:
                self.request1Text.getDocument().insertString(pos, self.PAYLOAD_PLACEHOLDER, None)
            except Exception as e:
                self._callbacks.printError("Insert failed: " + str(e))

        popupMenu = JPopupMenu()
        popupMenu.add(JMenuItem("Insert %s here" % self.PAYLOAD_PLACEHOLDER, actionPerformed=insertPayloadAction))

        class PopupListener(MouseAdapter):
            def mousePressed(self, e):
                if e.isPopupTrigger():
                    popupMenu.show(e.getComponent(), e.getX(), e.getY())
            def mouseReleased(self, e):
                if e.isPopupTrigger():
                    popupMenu.show(e.getComponent(), e.getX(), e.getY())

        self.request1Text.addMouseListener(PopupListener())

        self._btnPanel = JPanel()
        self._btnPanel.add(JButton("Load Wordlist", actionPerformed=self.loadWordlist))
        self._btnPanel.add(JButton("Start Attack", actionPerformed=self.startAttack))
        self._btnPanel.add(JButton("Clear", actionPerformed=self.clearAll))

        verticalSplit = JSplitPane(JSplitPane.VERTICAL_SPLIT)
        verticalSplit.setTopComponent(JScrollPane(self.resultTable))
        verticalSplit.setBottomComponent(self.bottomSplit)
        verticalSplit.setDividerLocation(200)

        self._mainPanel.removeAll()
        self._mainPanel.add(verticalSplit, BorderLayout.CENTER)
        self._mainPanel.add(self._btnPanel, BorderLayout.SOUTH)
        self._mainPanel.revalidate()
        self._mainPanel.repaint()

    def clearAll(self, event):
        self._callbacks.printOutput("Reloading Intruder2GET UI and state...")
        self._mainPanel.removeAll()
        self.selectedMessages = [None, None]
        self.payloads = []
        self.results = []
        self.request1State = {'req': '', 'resp': '', 'html': False, 'mode': 'request'}
        self.request2State = {'req': '', 'resp': '', 'html': False, 'mode': 'request'}
        self.tableModel.setRowCount(0)
        self.initUI()
        self._mainPanel.revalidate()
        self._mainPanel.repaint()

    def wrapHtml(self, body):
        return "<html><head><meta charset='UTF-8'></head><body>" + body + "</body></html>"

    def getTabCaption(self): return "Intruder2GET"
    def getUiComponent(self): return self._mainPanel

    def createMenuItems(self, invocation):
        messages = invocation.getSelectedMessages()
        if messages and len(messages) == 1:
            return [JMenuItem("Send to Intruder2GET", actionPerformed=lambda x: self.setRequest(messages[0]))]
        return []

    def setRequest(self, message):
        if self.selectedMessages[0] is None:
            self.selectedMessages[0] = message
            self.request1Text.setText(self._helpers.bytesToString(message.getRequest()))
        else:
            self.selectedMessages[1] = message
            self.request2Text.setText(self._helpers.bytesToString(message.getRequest()))
        self._callbacks.printOutput("Request set.")

    def loadWordlist(self, event):
        chooser = JFileChooser()
        if chooser.showOpenDialog(None) == JFileChooser.APPROVE_OPTION:
            with open(chooser.getSelectedFile().getAbsolutePath()) as f:
                self.payloads = [line.strip() for line in f if line.strip()]
            self._callbacks.printOutput("Loaded %d payloads." % len(self.payloads))

    def startAttack(self, event):
        threading.Thread(target=self.runAttack).start()

    def runAttack(self):
        self.tableModel.setRowCount(0)
        self.results = []
        if None in self.selectedMessages or not self.payloads:
            self._callbacks.printOutput("Load both requests and payloads first.")
            return

        baseStr1 = self.request1Text.getText()
        request2 = self.request2Text.getText()

        if self.PAYLOAD_PLACEHOLDER not in baseStr1:
            self._callbacks.printOutput("No '%s' placeholder found." % self.PAYLOAD_PLACEHOLDER)
            return

        for i, payload in enumerate(self.payloads):
            req1 = baseStr1.replace(self.PAYLOAD_PLACEHOLDER, payload)
            respStr1 = self._helpers.bytesToString(
                self._callbacks.makeHttpRequest(self.selectedMessages[0].getHttpService(),
                                                self._helpers.stringToBytes(req1)).getResponse())

            respStr2 = self._helpers.bytesToString(
                self._callbacks.makeHttpRequest(self.selectedMessages[1].getHttpService(),
                                                self._helpers.stringToBytes(request2)).getResponse())

            self.results.append((payload, req1, respStr1, request2, respStr2))
            self.tableModel.addRow([i + 1, payload, len(respStr1), len(respStr2)])

        self._callbacks.printOutput("Attack completed. %d payloads sent." % len(self.payloads))

    def rowSelected(self, event):
        if not event.getValueIsAdjusting():
            index = self.resultTable.getSelectedRow()
            if 0 <= index < len(self.results):
                if None in self.selectedMessages:
                    return
                _, req1, resp1, req2, resp2 = self.results[index]
                self.request1State['req'] = req1
                self.request1State['resp'] = resp1
                self.request2State['req'] = req2
                self.request2State['resp'] = resp2
                self.request1UpdateView()
                self.request2UpdateView()
